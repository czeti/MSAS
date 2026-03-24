/* Scan Started Task (STC) security */
trace off
address TSO

findings.   = ''
findings.0  = 0


x = outtrap('profile_list.')
'RLIST STARTED *'
x = outtrap('off')

if profile_list.0 = 0 then do
  call add_finding 'INFO', 'No STARTED profiles found'
  signal emit_findings
end


do i = 1 to profile_list.0
  line = profile_list.i
  if pos('CLASS=STARTED', line) > 0 then do
    parse var line . 'STARTED.' profile ' '
    profile = strip(profile)
    if profile = '' then iterate

    call add_finding 'INFO', 'Checking STARTED profile' profile

    x = outtrap('detail.')
    'RLIST STARTED ('profile') ALL'
    x = outtrap('off')

    user = ''
    do j = 1 to detail.0
      if pos('USER=', detail.j) > 0 then do
        parse var detail.j . 'USER=' user .
        user = strip(user)
      end
    end

    if user = '' then do
      call add_finding 'WARNING', ,
        'STARTED profile' profile 'has no assigned user'
      iterate
    end

    x = outtrap('userinfo.')
    'LISTUSER ('user')'
    x = outtrap('off')

    special = 0
    ops     = 0
    do j = 1 to userinfo.0
      if pos('SPECIAL',    userinfo.j) > 0 then special = 1
      if pos('OPERATIONS', userinfo.j) > 0 then ops    = 1
    end

    if special then
      call add_finding 'WARNING', ,
        'STARTED task' profile 'user' user 'has SPECIAL attribute'
    if ops then
      call add_finding 'WARNING', ,
        'STARTED task' profile 'user' user 'has OPERATIONS attribute'
    if \special & \ops then
      call add_finding 'INFO', ,
        'STARTED task' profile 'user' user 'has no excessive privileges'
  end
end

emit_findings:
say copies('-', 60)
say 'STC AUDIT FINDINGS:' findings.0 'item(s)'
say copies('-', 60)
if findings.0 = 0 then
  say 'INFO: No STC-related findings detected.'
else do i = 1 to findings.0
  say findings.i
end
say copies('-', 60)

exit 0

add_finding: procedure expose findings.
  parse arg severity, text
  n = findings.0 + 1
  findings.n = severity || ': ' || text
  findings.0 = n
return