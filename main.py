import os
import sys
import json
import hashlib
import datetime
from time import sleep
import winreg
import win32com.client
import win32gui
import win32con
import win32api
import ctypes
from pathlib import Path
from analyze_lnk import LNKAnalyzer
import shutil
# pip install pywin32 requests jinja2 matplotlib numpy

class WhitelistManager:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        self.whitelist_file = os.path.join(application_path, "whitelist.json")
        print(f"화이트리스트 파일 경로: {self.whitelist_file}")
        
        if not os.path.exists(self.whitelist_file):
            print(f"화이트리스트 파일이 없습니다. 새로 생성합니다: {self.whitelist_file}")
            self.whitelist = {}
            self.save_whitelist()
        else:
            self.whitelist = self.load_whitelist()

    def load_whitelist(self):
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"화이트리스트 로딩 실패: {e}")
            return {}

    def save_whitelist(self):
        try:
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(self.whitelist, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"화이트리스트 저장 실패: {e}")

    def calculate_hash(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            print(f"해시 계산 실패: {e}")
            return None

    def is_whitelisted(self, file_path):
        try:
            file_hash = self.calculate_hash(file_path)
            return file_hash in self.whitelist
        except Exception as e:
            print(f"화이트리스트 확인 실패: {e}")
            return False

    def add_to_whitelist(self, file_path, description=""):
        try:
            file_hash = self.calculate_hash(file_path)
            if file_hash:
                self.whitelist[file_hash] = {
                    "path": file_path,
                    "description": description,
                    "added_date": str(datetime.datetime.now())
                }
                self.save_whitelist()
                print(f"파일이 화이트리스트에 추가되었습니다: {file_path}")
                return True
            return False
        except Exception as e:
            print(f"화이트리스트 추가 실패: {e}")
            return False

class LNKHandler:
    def __init__(self):
        self.whitelist_mgr = WhitelistManager()
        self.shell = win32com.client.Dispatch("WScript.Shell")

    def setup_registry(self):
        try:
            self.backup_registry()
            
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.lnk') as key:
                winreg.SetValue(key, '', winreg.REG_SZ, 'LNKSafeExecute')

            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.lnks') as key:
                winreg.SetValue(key, '', winreg.REG_SZ, 'lnkfile')

            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, 'LNKSafeExecute') as key:
                with winreg.CreateKey(key, 'shell') as shell_key:
                    winreg.SetValue(shell_key, '', winreg.REG_SZ, 'lnkfile')
            
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, 'LNKSafeExecute\\shell\\open\\command') as key:
                cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}" "%1"'
                winreg.SetValue(key, '', winreg.REG_SZ, cmd)

            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, 'LNKSafeExecute\\ShellEx\\IconHandler') as key:
                with winreg.CreateKey(key, 'shell') as shell_key:
                    winreg.SetValue(shell_key, '', winreg.REG_SZ, '{00021401-0000-0000-C000-000000000046}')

            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, 'LNKSafeExecute\\shell\\runas\\command') as key:
                cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}" "%1"'
                winreg.SetValue(key, '', winreg.REG_SZ, cmd)

            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, 'LNKSafeExecute\\shell\\runas') as runas_key:
                winreg.SetValueEx(runas_key, '', 0, winreg.REG_SZ, '관리자 권한으로 실행')
            
            print("레지스트리 설정이 완료되었습니다.")
            return True
        except Exception as e:
            print(f"레지스트리 설정 실패: {e}")
            return False

    def backup_registry(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '.lnk', 0, winreg.KEY_READ) as key:
                value = winreg.QueryValue(key, '')
                with open('registry_backup.txt', 'w') as f:
                    f.write(value)
        except Exception as e:
            print(f"레지스트리 백업 실패: {e}")

    def restore_registry_from_backup(self):
        try:
            print("레지스트리 복원을 시도합니다.")
            if os.path.exists('registry_backup.txt'):
                with open('registry_backup.txt', 'r') as f:
                    original_value = f.read()
                
                with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.lnk') as key:
                    winreg.SetValue(key, '', winreg.REG_SZ, original_value)
                
                print("레지스트리 복원이 완료되었습니다.")
        except Exception as e:
            print(f"레지스트리 복원 실패: {e}")

    def restore_registry(self):
        try:
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.lnk') as key:
                winreg.SetValue(key, '', winreg.REG_SZ, 'lnkfile')
            
            self._delete_key_tree(winreg.HKEY_CLASSES_ROOT, 'LNKSafeExecute')
            
            print("레지스트리 삭제가 완료되었습니다.")
        except Exception as e:
            print(f"레지스트리 삭제 실패: {e}")
            self.restore_registry_from_backup()

    def _delete_key_tree(self, key, key_name):
        try:
            with winreg.OpenKey(key, key_name, 0, winreg.KEY_ALL_ACCESS) as opened_key:
                while True:
                    try:
                        subkey = winreg.EnumKey(opened_key, 0)
                        self._delete_key_tree(opened_key, subkey)
                    except WindowsError:
                        break
            winreg.DeleteKey(key, key_name)
        except WindowsError:
            pass

    def execute_lnk(self, lnk_path):
        application_path = os.path.dirname(os.path.abspath(__file__))
        temp_file = os.path.join(application_path, "temp.lnks")
        try:
            temp_file2 = f"{lnk_path}s"
            if (os.path.exists(temp_file2)):
                os.remove(temp_file2)
            shutil.copy2(lnk_path, temp_file2)
            os.startfile(temp_file2)
        except Exception as e:
            print(f"파일 디렉토리의 임시 LNKS 파일 실행 실패: {e}")
            try:
                if (os.path.exists(temp_file)):
                    os.remove(temp_file)
                shutil.copy2(lnk_path, temp_file)
                os.startfile(temp_file)
            except:
                print(f"스크립트 디렉토리의 임시 LNKS 파일 실행 실패: {e}")
                try:
                    shortcut = self.shell.CreateShortCut(lnk_path)
                    target_path = shortcut.Targetpath
                    arguments = shortcut.Arguments
                    working_dir = shortcut.WorkingDirectory

                    if working_dir:
                        os.chdir(working_dir)
                    
                    if arguments:
                        os.system(f'"{target_path}" {arguments}')
                    else:
                        os.startfile(target_path)
                    
                    return True
                except Exception as e:
                    print(f"LNK 파일 실행 실패: {e}")
                    try:
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv, None, 1))
                    except Exception as e:
                        print(f"관리자 권한 획득 실패: {e}")
                        sleep(2)
                        
        finally:
            if (os.path.exists(temp_file)):
                os.remove(temp_file)
            if (os.path.exists(temp_file2)):
                os.remove(temp_file2)
            print(f"임시 파일 모두 삭제")

    def handle_lnk_file(self, lnk_path):
        try:
            print(f"LNK 파일 감지: {lnk_path}")
            
            if self.whitelist_mgr.is_whitelisted(lnk_path):
                print("화이트리스트에 등록된 파일입니다.")
                return self.execute_lnk(lnk_path)
            
            risk_score = LNKAnalyzer(lnk_path, " ").analyze()
            print(f"위험도 점수: {risk_score}")
            
            if risk_score > 4:
                win32gui.MessageBox(0, 
                    "위험한 LNK 파일이 감지되었습니다!\n실행이 차단되었습니다.", 
                    "보안 경고", 
                    win32con.MB_ICONWARNING)
                return False
            
            if risk_score <= 4:
                response = win32gui.MessageBox(0, 
                    "이 파일을 화이트리스트에 추가하시겠습니까?",
                    "화이트리스트",
                    win32con.MB_YESNO)
                
                if response == win32con.IDYES:
                    self.whitelist_mgr.add_to_whitelist(lnk_path, "사용자 승인으로 추가됨")
            
            return self.execute_lnk(lnk_path)
            
        except Exception as e:
            print(f"LNK 파일 처리 중 오류 발생: {e}")
            sleep(2)
            return False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        lnk_path = sys.argv[1]
        handler = LNKHandler()
        handler.handle_lnk_file(lnk_path)
    else:
        if not is_admin():
            print("관리자 권한이 필요합니다.")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        else:
            handler = LNKHandler()
            if handler.setup_registry():
                print("LNK 파일 보안 처리기가 설치되었습니다.")
                input("아무 키나 누르면 종료됩니다...")