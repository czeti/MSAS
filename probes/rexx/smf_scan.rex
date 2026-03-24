/* Extract SMF security records (types 80, 40) */
trace off
address TSO

findings.   = ''
findings.0  = 0


call parse_smf

/* helper label */
emit_findings:
say copies('-', 60)
say 'SMF AUDIT FINDINGS:' findings.0 'item(s)'
say copies('-', 60)
if findings.0 = 0 then
  say 'INFO: No SMF findings detected (SMF data may not be available).'
else do i = 1 to findings.0
  say findings.i
end
say copies('-', 60)

exit 0

/* run smf list and classify records */
parse_smf: procedure expose findings.
  x = outtrap('smf_out.')
  'SMF LIST'
  x = outtrap('off')

  do i = 1 to smf_out.0
    line = smf_out.i

    if pos('TYPE 80', line) > 0 then do
      parse var line ,
        . 'USER='     user     ,
        . 'RESOURCE=' resource ,
        . 'ACTION='   action   ,
        . 'RESULT='   result   .
      if result = 'FAILED' then
        call add_finding 'WARNING', ,
          'Failed RACF login: user=' user ,
          ' resource=' resource
      else if result = 'SUCCESS' then
        call add_finding 'INFO', ,
          'Successful RACF login: user=' user ,
          ' resource=' resource
    end
    else if pos('TYPE 40', line) > 0 then do
      parse var line ,
        . 'USER='    user   ,
        . 'DATASET=' dsname ,
        . 'ACCESS='  access .
      if access = 'READ' then
        call add_finding 'INFO', ,
          'Dataset read: user=' user ' dataset=' dsname
      else if access = 'UPDATE' | access = 'ALTER' then
        call add_finding 'WARNING', ,
          'Dataset update/alter: user=' user ,
          ' dataset=' dsname ' access=' access
    end
  end
return


add_finding: procedure expose findings.
  parse arg severity, text
  n = findings.0 + 1
  findings.n = severity || ': ' || text
  findings.0 = n
return