trace off /* turn off stdout */
address TSO /* redirect literal rexx commands into TSO address space */

findings. = ''
findings.0 = 0
flagged_special. = 0

x = outtrap('raw.')
'LISTUSER *'
x = outtrap('off')

currentUser = ''
do i = 1 to raw.0 /* raw.0 contains line numbers retrieved */
    line = raw.i
    if pos('USER=', line) then do
        parse var line . 'USER=' rest
        parse var rest currentUser .
        currentUser = strip(currentUser)
    end

    if currentUser \= '' then do
        
        /* check for special attributes */
        if pos('SPECIAL', line) > 0  then do
            if flagged_special.currentUser = 0 then do
                call add_findings 'WARNING: User' currentUser,
                'has SPECIAL attributes (Highly privileged)'
                flagged_special.currentUser = 1
            end
        end    

        /* check password interval*/
        if pos('PASS-INTERVAL=', line) > 0 then do
            parse var line . 'PASS-INTERVAL=' rest
            parse var rest interval .
            if strip(interval) = '0' then do
                call add_findings 'WARNING: User' currentUser,
                'password never expires'
            end
        end

        /* check if this user has been revoked */
        if pos('REVOKE DATE=', line) > 0 then do
            parse var line . 'REVOKE DATE=' rest
            parse var rest rdate .
            if strip(rdate) \= 'NONE' then do
                call add_findings 'WARNING: User' currentUser,
                'has been revoked (' strip(rdate) ')'
            end
        end
    end
end

/* hard coded default check */
call add_findings 'WARNING: Ensure IBMUSER user account default password',
'has been changed'

say copies('-', 60)
say 'RACF Audit findings: ' findings.0 'item(s)'
say copies('-', 60)

if findings.0 = 0 then
    say 'INFO: No RACF Findings'
else do i = 1 to findings.0
    say findings.i
end

say copies('-', 60)
exit 0

add_findings: procedure expose findings.
    parse arg severity, text
    n = findings.0 + 1
    findings.n = severity || ':' || text
    findings.0 = n
return