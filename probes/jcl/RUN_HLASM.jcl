//%MEMBER%  JOB (ACCT),'HLASM PROBE',CLASS=A,MSGCLASS=A,
//             REGION=4M,NOTIFY=&SYSUID
//ASM      EXEC PGM=ASMA90,
//             PARM='NOTERM,ALIGN'
//SYSLIB   DD  DISP=SHR,DSN=SYS1.MACLIB
//         DD  DISP=SHR,DSN=SYS1.MODGEN
//SYSUT1   DD  UNIT=SYSDA,SPACE=(CYL,(1,1))
//SYSUT2   DD  UNIT=SYSDA,SPACE=(CYL,(1,1))
//SYSUT3   DD  UNIT=SYSDA,SPACE=(CYL,(1,1))
//SYSPRINT DD  DSN=%LISTING_DSN%,
//             DISP=(NEW,CATLG,DELETE),
//             UNIT=SYSALLDA,
//             SPACE=(TRK,(3,1)),
//             DCB=(RECFM=FB,LRECL=133,BLKSIZE=1330)
//SYSLIN   DD  DSN=&&OBJ,DISP=(MOD,PASS),UNIT=SYSDA,
//             SPACE=(TRK,(1,1)),DCB=(RECFM=FB,LRECL=80)
//SYSIN    DD  DISP=SHR,DSN=IBMUSER.PROBES.ASM(%MEMBER%)
//*-------------------------------------------------------------------
//* linkage editor (LKED).
//* SYSLMOD uses a temp PDS so no pre existing or predefined LOADLIB is
//* required.
//*-------------------------------------------------------------------
//LKED     EXEC PGM=HEWL,COND=(4,LT,ASM),
//             PARM='REUS,REFR'
//SYSLIB   DD  DISP=SHR,DSN=SYS1.LINKLIB
//SYSLIN   DD  DISP=(OLD,DELETE),DSN=&&OBJ
//SYSLMOD  DD  DSN=&&LOADMOD(%MEMBER%),DISP=(NEW,PASS),
//             UNIT=SYSDA,SPACE=(TRK,(1,1,1)),
//             DCB=(RECFM=U,BLKSIZE=32760)
//SYSPRINT DD  SYSOUT=*
//*-------------------------------------------------------------------
//* run
//*-------------------------------------------------------------------
//GO       EXEC PGM=%MEMBER%,COND=((4,LT,ASM),(4,LT,LKED))
//STEPLIB  DD  DSN=&&LOADMOD,DISP=(OLD,DELETE)
//SYSPRINT DD  DSN=%OUTPUT_DSN%,
//             DISP=(NEW,CATLG,DELETE),
//             UNIT=SYSALLDA,
//             SPACE=(TRK,(1,1)),
//             DCB=(RECFM=FB,LRECL=133,BLKSIZE=1330)
//SYSOUT   DD  SYSOUT=*