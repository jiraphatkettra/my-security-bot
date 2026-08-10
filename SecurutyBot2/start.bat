@echo off
title Ultimate Enterprise Security Bot
color 0a

:START
cls
echo ==========================================
echo  Ultimate Enterprise Security Bot
echo  System is starting...
echo ==========================================
echo.

:: รันไฟล์ main.py ด้วย python
python main.py

:: หากบอทดับหรือแครช จะมาทำงานในส่วนนี้
echo.
echo ==========================================
echo [Warning] Bot has stopped or crashed!
echo Restarting in 5 seconds...
echo ==========================================
timeout /t 5 /nobreak >nul

goto START