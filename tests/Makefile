default: runtests

clean:
	find . -name '*__pycache__' -exec rm -rf {} +
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*-inline-scan.xml' -exec rm -f {} +

lint:
	flake8

runtests:
	pipenv install -d
	pipenv run nosetests