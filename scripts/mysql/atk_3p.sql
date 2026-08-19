-- atk_3p.sql — attribution poisoning from within (MySQL analogue of Experiment 3).
-- Run as app_user. Precondition: broad INSERT grant on labdb.audit_logged_actions.
-- Fabricate a fully synthetic, back-dated identity decoupled from any real request.
INSERT INTO labdb.audit_logged_actions(table_name,action,row_data,changed_by,client_host,logged_at)
VALUES('app_accounts','U',
       JSON_OBJECT('note','sentinel-3P-decoy'),
       'ghost_user_42@203.0.113.77',              -- non-existent user (synthetic)
       '203.0.113.77',                            -- RFC 5737 documentation IP (fake)
       NOW() - INTERVAL 3 DAY);                    -- backdated decoy
