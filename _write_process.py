import base64, sys
# base64 content written separately
b64 = sys.argv[1]
data = base64.b64decode(b64)
with open(r'F:\winDriver\te\Ophion-master\PROCESS.md', 'wb') as f:
    f.write(data)
print(f'Written {len(data)} bytes')
