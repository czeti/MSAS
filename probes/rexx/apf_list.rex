/* Scans APF‑authorized datasets for weak permissions */
trace off
address TSO

findings.   = ''
findings.0  = 0


x = outtrap('profile_list.')
'SEARCH CLASS(PROGRAM)' /* get list of program profiles (candidates) */
x = outtrap('off')

if profile_list.0 = 0 then do
  call add_finding 'INFO', 'No PROGRAM profiles found'
  signal emit_findings
end

/* for each profile, check if it has APF attribute and get dataset name */
do i = 1 to profile_list.0
  profile = strip(profile_list.i)
  if profile = '' then iterate

  x = outtrap('rlist_output.')
  'RLIST PROGRAM ('profile') ALL'
  x = outtrap('off')

  apf_flag = 0
  dsname   = ''
  do j = 1 to rlist_output.0
    line = rlist_output.j
    if pos('APF=', line) > 0 then do
      parse var line . 'APF=' apfval .
      if strip(apfval) = 'YES' then apf_flag = 1
    end
    if pos('DSNAME=', line) > 0 then do
      parse var line . 'DSNAME=' dsname .
      dsname = strip(dsname)
    end
  end

  if apf_flag = 0 then iterate   /* not APF‑authorized */

  /* if it gets here, you have an apf authorized program profile */
  if dsname = '' then do
    call add_finding 'INFO', 'APF profile' profile 'has no associated dataset'
    iterate
  end

  /* check dataset permissions via LISTDSD */
  x = outtrap('dsd_output.')
  'LISTDSD DATASET('''dsname''')'
  x = outtrap('off')

  uacc    = ''
  id_star = 0
  do j = 1 to dsd_output.0
    line = dsd_output.j
    if pos('UACC=', line) > 0 then do
      parse var line . 'UACC=' uacc .
      uacc = strip(uacc)
    end
    if pos('ID=', line) > 0 then do
      parse var line . 'ID=' id .
      if strip(id) = '*' then id_star = 1
    end
  end

  if uacc = '' then do
    call add_finding 'INFO', 'No RACF protection for APF dataset' dsname
  end
  else do
    if uacc = 'READ' | uacc = 'UPDATE' | uacc = 'ALTER' then
      call add_finding 'WARNING', 'APF dataset' dsname 'has UACC('uacc')'

    if id_star then
      call add_finding 'WARNING', 'APF dataset' dsname 'grants access to ID(*)'
  end
end

emit_findings:
say copies('-', 60)
say 'APF AUDIT FINDINGS:' findings.0 'item(s)'
say copies('-', 60)
if findings.0 = 0 then
  say 'INFO: No APF‑related findings detected.'
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