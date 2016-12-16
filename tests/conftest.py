import sys


sys.modules['idaapi'] = __import__('mockidaapi')
sys.modules['idc'] = __import__('mockidc')
