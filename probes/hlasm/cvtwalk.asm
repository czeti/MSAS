* Walk the CVT to list APF entries directly from storage.  *
         PRINT NOGEN
CVTWALK  CSECT
         STM   14,12,12(13)
         LR    12,15
         USING CVTWALK,12
         ST    13,SAVEAREA+4
         LA    13,SAVEAREA
         OPEN  (SYSPRINT,(OUTPUT))

         L     2,16                  load psa pointer (cvt) into r2
         LTR   2,2
         BZ    NO_CVT

         USING CVT,2
         L     3,CVTAPF              put first apf table in r3
         DROP  2
         LTR   3,3
         BZ    NO_APF_TABLE

         LA    4,0                   loop counter
LOOP     LH    5,0(3)               apf entry length
         LTR   5,5                  
         BZ    END_LOOP
         CH    5,=H'52'             skip malformed entries
         BL    SKIP_ENTRY
         MVC   MSG+25(44),2(3)      
         MVC   MSG+74(6),46(3)      
         PUT   SYSPRINT,MSG
         LA    4,1(4)               incrememnt entry counter
SKIP_ENTRY AR  3,5                  move to next entry
         B     LOOP
END_LOOP DS    0H

         CVD   4,WORK
         UNPK  COUNTBUF,WORK
         OI    COUNTBUF+7,X'F0'
         MVC   MSG2+25(4),COUNTBUF+4
         PUT   SYSPRINT,MSG2
         B     EXIT
NO_CVT   DS    0H
         PUT   SYSPRINT,ERRCVT
         B     EXIT
NO_APF_TABLE DS 0H
         PUT   SYSPRINT,ERRNOAPF
         B     EXIT
EXIT     CLOSE (SYSPRINT)
         L     13,SAVEAREA+4
         LM    14,12,12(13)
         SR    15,15
         BR    14

SAVEAREA DC    18F'0'
WORK     DS    D
COUNTBUF DC    CL8' '
MSG      DC    CL133'INFO: APF entry: dataset=XXXXXXXXXXXXXXXXXXXXXXXXX+
               XXXXXXXXXXXXXXXXXXX vol=VVVVVV'
MSG2     DC    CL133'INFO: Total APF entries: NNNN'
ERRCVT   DC    CL133'WARNING: CVT address not found'
ERRNOAPF DC    CL133'WARNING: No APF table found'
SYSPRINT DCB   DDNAME=SYSPRINT,                                        X
               DSORG=PS,                                               X
               RECFM=FB,                                               X
               LRECL=133,                                              X
               BLKSIZE=1330,                                           X
               MACRF=PM
         CVT   DSECT=YES
         END   CVTWALK