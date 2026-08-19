import json
p={'sender':'+15559876543','body':'Hello, are you available?','is_saved_contact':False}
with open('tests/contact_ct02.json','w',encoding='utf-8') as f:
    json.dump(p,f)
print('wrote')
