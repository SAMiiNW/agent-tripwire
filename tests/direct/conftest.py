import os
_unlink=os.unlink
def safe_unlink(path,*args,**kwargs):
 try:return _unlink(path,*args,**kwargs)
 except PermissionError:return None
os.unlink=safe_unlink
CONTRACT=os.path.join('contracts','contract.py')

