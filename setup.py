from setuptools import setup, find_packages

version = '0.0.1-SNAPSHOT'

setup(
    name='ckanext-csrf-filter',
    version=version,
    description='Protect against CSRF attacks',
    long_description="""Use cryptographically strong tokens to protect against Cross-Site Request Forgery""",
    classifiers=[],
    keywords='',
    author='Queensland Online',
    author_email='qol.development@smartservice.qld.gov.au',
    url='',
    license='',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    entry_points="""
    [ckan.plugins]
    csrf=\
ckanext.csrf_filter.plugin:CSRFFilterPlugin
    """,
)
