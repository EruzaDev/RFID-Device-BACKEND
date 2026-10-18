-- Apply before deploying the API and flashing the new firmware.
begin;
alter table public.device_state drop constraint if exists device_state_stage_check;
alter table public.device_state add constraint device_state_stage_check
  check (stage in ('idle', 'scan_student', 'checking_student', 'scan_item', 'checking_item',
    'wrong_tag', 'confirm', 'saving', 'retry_confirm', 'cancelled', 'success', 'error'));
alter table public.device_state add column if not exists error_code text;
alter table public.device_state add constraint device_state_error_code_check check (
  error_code is null or (stage in ('error', 'retry_confirm') and error_code in (
    'student_unknown', 'item_unknown', 'already_borrowed', 'wrong_borrower', 'bad_uid',
    'clock_skew', 'auth_failed', 'replay', 'request_reused', 'server_error',
    'bridge_offline', 'api_unreachable', 'unknown'))
);
commit;
