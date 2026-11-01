from pathlib import Path
import importlib.util
import os
from unittest.mock import patch

root=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('settings',root/'src/settings.py')
settings=importlib.util.module_from_spec(spec); spec.loader.exec_module(settings)
for url in ['http://127.0.0.1:11434','http://localhost:11434','http://10.20.30.40:11434','https://[fd00::1]:11434']:
    assert settings.local_url(url)==url
for url in ['https://ollama.com','http://8.8.8.8','http://0.0.0.0','http://user:password@localhost','http://localhost/api','http://localhost/?token=x','file:///tmp/socket']:
    try: settings.local_url(url)
    except ValueError: pass
    else: raise AssertionError('Non-local or ambiguous URL accepted: '+url)
for model in ['example:cloud','model-cloud','bad model']:
    try: settings.local_model(model)
    except ValueError: pass
    else: raise AssertionError('Bad model accepted')
with patch.dict(os.environ, {'AI_MONITOR_MODEL':'qwen3:8b','AI_MONITOR_TIMEZONE':'UTC','AI_MONITOR_HOME_NAS':'home.example.invalid'}, clear=True):
    config=settings.load()
    assert config['timezone']=='UTC' and config['home_nas']=='home.example.invalid'
    assert config['ollama_url']=='http://127.0.0.1:11434'
    assert config['viewer_origin']=='http://127.0.0.1:8088' and not config['controls_enabled']
with patch.dict(os.environ, {'AI_MONITOR_CONTROLS':'1','AI_MONITOR_VIEWER_ORIGIN':'http://10.20.30.40:8088'}, clear=True):
    assert settings.load()['controls_enabled']
    assert settings.load()['viewer_origin']=='http://10.20.30.40:8088'
for values in ({'AI_MONITOR_CONTROLS':'true'}, {'AI_MONITOR_VIEWER_ORIGIN':'https://public.example.com'}):
    with patch.dict(os.environ,values,clear=True):
        try: settings.load()
        except ValueError: pass
        else: raise AssertionError('Invalid controls setting accepted')
print('PASS: configurable model/timezone/NAS; private-origin validation; cloud tags, credentials and URL paths rejected. No network used.')
