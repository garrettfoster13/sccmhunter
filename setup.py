from setuptools import setup

with open('requirements.txt', 'r', encoding='utf-8') as fin:
  requirements = [i.strip() for i in fin.readlines()]

setup(
  name='sccmhunter',
  install_requires=requirements,
  scripts = ['sccmhunter.py'],
)
