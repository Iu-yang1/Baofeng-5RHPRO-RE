//! OEM V2 menu-state monitor and independent interactive configuration UI.
//!
//! Source-proven monitor: 0x080167B8..0x0801681C, working UI status
//! at 0x20000104, active bit0 from 0x2000182A, selected ID from
//! 0x0800E064, previous ID from 0x0800D010. It is *one poll function*,
//! not a recovered complete OEM display/menu event loop.
//!
//! The ergonomic editing actions are an independent firmware interface,
//! not an assertion that unknown physical key legends or OEM layout have
//! been identified. They reuse the confirmed getter/setter/NV contracts.

use crate::oem_config_getter::OemWorkingConfig;
use crate::oem_config_setter::{
    apply_original_setter, original_nv_address, LogicalNvJournal, OemSetterPreCall,
};
use crate::oem_menu::{OriginalConfigId, OEM_CONFIG_COUNT};
use crate::oem_nv_compat::{
    commit_with_layout, OemCompatWriteError, OemNvWriteLayout,
};

pub const OEM_MENU_STATUS_SRAM:u32=0x2000_0104;
pub const OEM_MENU_ACTIVITY_BYTE_SRAM:u32=0x2000_182A;
pub const OEM_MENU_FLAG:u16=0x0080;
pub const OEM_MENU_POLL_ENTRY:u32=0x0801_67B8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OemMenuPollState {
    pub state_byte:u8,
    pub flags:u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OemMenuSelection {
    pub active:bool,
    pub selected_id:u8,
    pub previous_id:u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OemMenuPollResult {
    /// Original 0x08016812..0x0801681A clears flag 7 and sets state 4.
    ClearAndGoState4,
    /// Original 0x080167D6..0x080167F4 calls UI refresh helpers.
    /// 0xFFFF is the source-proven sentinel when getter returns zero.
    Refresh {
        selected_id:u8,
        config_value:u8,
        original_aux_value:Option<u8>,
        fallback_marker:u16,
    },
    NoRefresh,
}

impl OemMenuPollState {
    pub const fn new(state_byte:u8,flags:u16)->Self {
        Self {state_byte,flags}
    }

    /// This pure transition returns *requests* for the OEM opaque
    /// downstream drawing helpers; they are not executed here.
    pub fn tick(&mut self,input:OemMenuSelection,
        config:&mut OemWorkingConfig,
        original_aux:Option<u8>)->OemMenuPollResult {
        if self.flags & OEM_MENU_FLAG != 0 {
            self.flags &= !OEM_MENU_FLAG;
            self.state_byte=4;
            return OemMenuPollResult::ClearAndGoState4;
        }
        let outcome=if input.active && input.selected_id!=input.previous_id {
            let value=config.read(OriginalConfigId(input.selected_id));
            OemMenuPollResult::Refresh {
                selected_id:input.selected_id,
                config_value:value,
                original_aux_value:if value==0 {None} else {original_aux},
                fallback_marker:if value==0 {0xFFFF} else {0},
            }
        } else {
            OemMenuPollResult::NoRefresh
        };
        if self.state_byte==0 {self.state_byte=1;}
        self.flags |= OEM_MENU_FLAG;
        outcome
    }
}

/// Logical, not physical keypad, actions for the new independent UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction { Next, Previous, BeginEdit, Increment, Decrement, Cancel }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuMode {
    Browse,
    Edit { value:u8, original_value:u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MenuScreenState {
    pub config_id:u8,
    pub current_value:u8,
    pub visible_value:u8,
    pub editing:bool,
    pub changed:bool,
    pub write_supported:bool,
}

pub struct IndependentMenu {
    pub selected_id:u8,
    pub mode:MenuMode,
}

impl IndependentMenu {
    pub const fn new()->Self {
        Self {selected_id:0,mode:MenuMode::Browse}
    }
    pub fn action(&mut self, action:MenuAction,working:&mut OemWorkingConfig) {
        match (self.mode,action) {
            (MenuMode::Browse,MenuAction::Next) =>
                self.selected_id=(self.selected_id+1) % OEM_CONFIG_COUNT as u8,
            (MenuMode::Browse,MenuAction::Previous) =>
                self.selected_id=(self.selected_id+OEM_CONFIG_COUNT as u8-1)
                    % OEM_CONFIG_COUNT as u8,
            (MenuMode::Browse,MenuAction::BeginEdit) => {
                let original=working.read(OriginalConfigId(self.selected_id));
                self.mode=MenuMode::Edit{value:original,original_value:original};
            }
            (MenuMode::Edit{value,original_value},MenuAction::Increment) =>
                self.mode=MenuMode::Edit{value:value.wrapping_add(1),original_value},
            (MenuMode::Edit{value,original_value},MenuAction::Decrement) =>
                self.mode=MenuMode::Edit{value:value.wrapping_sub(1),original_value},
            (MenuMode::Edit{..},MenuAction::Cancel) =>
                self.mode=MenuMode::Browse,
            _ => {},
        }
    }

    pub fn screen(&self,working:&mut OemWorkingConfig)->MenuScreenState {
        let current=working.read(OriginalConfigId(self.selected_id));
        let (visible,editing,changed)=match self.mode {
            MenuMode::Browse => (current,false,false),
            MenuMode::Edit{value,original_value} =>
                (value,true,value!=original_value),
        };
        MenuScreenState {
            config_id:self.selected_id,
            current_value:current,visible_value:visible,
            editing,changed,
            write_supported:original_nv_address(self.selected_id).is_some(),
        }
    }

    /// Explicit handler for original side-effecting setter cases. The
    /// original helpers are invoked BEFORE writing the configuration.
    /// The menu keeps the draft if either helper or logical NV fails.
    pub fn confirm<W:LogicalNvJournal,H:OemSetterHelper>(
        &mut self,
        working:&mut OemWorkingConfig,
        nv:&mut W,
        helper:&mut H,
        layout:OemNvWriteLayout,
        persist:bool,
    )->Result<MenuCommitOutcome,MenuCommitError<W::Error,H::Error>> {
        let MenuMode::Edit{value,..}=self.mode else {
            return Ok(MenuCommitOutcome::NotEditing);
        };
        let mut next=working.clone();
        let Some(mutation)=apply_original_setter(
            &mut next,self.selected_id,value,if persist {1} else {0}
        ) else {
            self.mode=MenuMode::Browse;
            return Ok(MenuCommitOutcome::OriginalSetterNoOp);
        };
        if let Some(pre_call)=mutation.pre_call {
            helper.invoke(pre_call,value).map_err(MenuCommitError::Helper)?;
        }
        let written=commit_with_layout(&mutation,layout,nv)
            .map_err(MenuCommitError::Journal)?;
        *working=next;
        self.mode=MenuMode::Browse;
        Ok(MenuCommitOutcome::Applied {
            written_address:written,
            written_value:mutation.working_value,
        })
    }
}

/// Adapter for the two original callsites whose hardware functions are
/// still opaque. Using a no-op implementation for these two settings
/// would falsely claim complete on-board operation.
pub trait OemSetterHelper {
    type Error;
    fn invoke(&mut self,callee:OemSetterPreCall,raw_value:u8)->Result<(),Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum MenuCommitError<NV,H> {
    Helper(H),
    Journal(OemCompatWriteError<NV>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuCommitOutcome {
    NotEditing,
    OriginalSetterNoOp,
    Applied{written_address:Option<u32>,written_value:u8},
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::oem_config_getter::OEM_CONFIG_STORAGE_LEN;
    use std::vec::Vec;

    #[derive(Default)]
    struct Recorder {
        writes:Vec<(u32,u8)>, fail:bool,
    }
    impl LogicalNvJournal for Recorder {
        type Error=&'static str;
        fn update_one(&mut self,addr:u32,value:u8)->Result<(),Self::Error>{
            if self.fail {return Err("NV");}
            self.writes.push((addr,value));Ok(())
        }
    }
    #[derive(Default)]
    struct Helpers {calls:Vec<(OemSetterPreCall,u8)>, fail:bool}
    impl OemSetterHelper for Helpers {
        type Error=&'static str;
        fn invoke(&mut self,hook:OemSetterPreCall,value:u8)->Result<(),Self::Error>{
            if self.fail {return Err("helper");}
            self.calls.push((hook,value));Ok(())
        }
    }

    #[test]
    fn source_monitor_tracks_activity_selection_refresh_and_state_flag() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        config.bytes[2]=5;
        let mut state=OemMenuPollState::new(0,0);
        assert_eq!(state.tick(OemMenuSelection{
            active:true,selected_id:2,previous_id:1,
        },&mut config,Some(42)),OemMenuPollResult::Refresh{
            selected_id:2,config_value:5,original_aux_value:Some(42),
            fallback_marker:0,
        });
        assert_eq!(state,OemMenuPollState::new(1,0x80));
        assert_eq!(state.tick(OemMenuSelection{
            active:false,selected_id:2,previous_id:1,
        },&mut config,None),OemMenuPollResult::ClearAndGoState4);
        assert_eq!(state,OemMenuPollState::new(4,0));
        assert_eq!(state.tick(OemMenuSelection{
            active:true,selected_id:2,previous_id:2,
        },&mut config,None),OemMenuPollResult::NoRefresh);
    }

    #[test]
    fn source_zero_value_requests_original_ffff_fallback() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut state=OemMenuPollState::new(5,0);
        assert_eq!(state.tick(OemMenuSelection{
            active:true,selected_id:3,previous_id:2,
        },&mut config,Some(8)),OemMenuPollResult::Refresh{
            selected_id:3,config_value:0,original_aux_value:None,
            fallback_marker:0xFFFF,
        });
    }

    #[test]
    fn independent_editor_navigates_all_67_read_cases_and_cancels_without_writes() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut menu=IndependentMenu::new();
        menu.action(MenuAction::Previous,&mut config);
        assert_eq!(menu.selected_id,66);
        menu.action(MenuAction::Next,&mut config);
        assert_eq!(menu.selected_id,0);
        menu.action(MenuAction::BeginEdit,&mut config);
        menu.action(MenuAction::Decrement,&mut config);
        assert_eq!(menu.screen(&mut config).visible_value,255);
        menu.action(MenuAction::Cancel,&mut config);
        assert_eq!(menu.screen(&mut config).visible_value,0);
        assert_eq!(config.bytes,[0;OEM_CONFIG_STORAGE_LEN]);
    }

    #[test]
    fn menu_confirm_writes_loader_aligned_value_and_commits_only_once() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut menu=IndependentMenu {selected_id:13,mode:MenuMode::Browse};
        menu.action(MenuAction::BeginEdit,&mut config);
        for _ in 0..7 {menu.action(MenuAction::Increment,&mut config);}
        let mut journal=Recorder::default();
        let mut helper=Helpers::default();
        assert_eq!(menu.confirm(&mut config,&mut journal,&mut helper,
            OemNvWriteLayout::LoaderConsistent,true),Ok(MenuCommitOutcome::Applied{
                written_address:Some(0x7993),written_value:7,
            }));
        assert_eq!(journal.writes,std::vec![(0x7993,7)]);
        assert_eq!(config.bytes[12],7);
        assert_eq!(menu.mode,MenuMode::Browse);
    }

    #[test]
    fn original_helper_executes_before_change_and_errors_keep_editing_draft() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut menu=IndependentMenu{selected_id:35,mode:MenuMode::Edit{
            value:1,original_value:0,
        }};
        let mut journal=Recorder::default();
        let mut helpers=Helpers{fail:true,..Helpers::default()};
        assert_eq!(menu.confirm(&mut config,&mut journal,&mut helpers,
            OemNvWriteLayout::OriginalSetter,true),Err(MenuCommitError::Helper("helper")));
        assert_eq!(config.bytes[24],0);
        assert!(journal.writes.is_empty());
        assert!(matches!(menu.mode,MenuMode::Edit{..}));
        helpers.fail=false;
        assert_eq!(menu.confirm(&mut config,&mut journal,&mut helpers,
            OemNvWriteLayout::OriginalSetter,true),Ok(MenuCommitOutcome::Applied{
                written_address:Some(0x79A3),written_value:0x80,
            }));
        assert_eq!(helpers.calls,std::vec![(OemSetterPreCall::SoftwareHelperDa10,1)]);
    }

    #[test]
    fn journal_failure_retains_draft_and_does_not_misreport_save_success() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut menu=IndependentMenu{selected_id:2,mode:MenuMode::Edit{
            value:9,original_value:0,
        }};
        let mut journal=Recorder {fail:true,..Recorder::default()};
        let mut helpers=Helpers::default();
        assert_eq!(menu.confirm(&mut config,&mut journal,&mut helpers,
            OemNvWriteLayout::LoaderConsistent,true),
            Err(MenuCommitError::Journal(OemCompatWriteError::Journal("NV"))));
        assert_eq!(config.bytes[2],0);
        assert!(matches!(menu.mode,MenuMode::Edit{..}));
        journal.fail=false;
        assert_eq!(menu.confirm(&mut config,&mut journal,&mut helpers,
            OemNvWriteLayout::LoaderConsistent,true),Ok(MenuCommitOutcome::Applied{
                written_address:Some(0x7986),written_value:9,
            }));
    }

    #[test]
    fn original_noop_setter_is_browsable_but_not_falsely_saved() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut menu=IndependentMenu{selected_id:32,mode:MenuMode::Browse};
        assert!(!menu.screen(&mut config).write_supported);
        menu.action(MenuAction::BeginEdit,&mut config);
        let mut journal=Recorder::default();
        let mut helper=Helpers::default();
        assert_eq!(menu.confirm(&mut config,&mut journal,&mut helper,
            OemNvWriteLayout::OriginalSetter,true),
            Ok(MenuCommitOutcome::OriginalSetterNoOp));
        assert!(journal.writes.is_empty());
    }
}
