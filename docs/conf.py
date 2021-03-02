# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
#import sphinx_rtd_theme
import sphinx_bootstrap_theme
import subprocess
import pathlib
from pathlib import Path

def generate_doxygen():
    # The Doxygen directory is one level up, so go there.
    parent_dir = Path(__file__).absolute().parent.parent

    # We don't catch any of the exceptions that could be thrown here because we want the build to fail if something
    # exceptional happens.
    p = subprocess.Popen(['doxygen', 'Doxygen/Doxyfile'], cwd=parent_dir)
    # A generous timeout.
    p.wait(timeout=120)
    if p.returncode != 0:
        print("Doxygen generation failed!")
        sys.exit(1)

generate_doxygen()

# -- Project information -----------------------------------------------------

project = 'Hypervisor Memory Introspection'
copyright = '2020, Bitdefender'
author = 'Bitdefender'

# The major project version, used as the replacement for |version|.
version = "1"
# The full project version, used as the replacement for |release| and e.g. in the HTML templates.
release = '1.132.1'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.autosectionlabel',
    'sphinx_bootstrap_theme'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# Tell sphinx what the primary language being documented is.
primary_domain = 'c'

# Tell sphinx what the pygments highlight language should be.
highlight_language = 'c'

todo_include_todos = False

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', 'chapters/global-options.rst', 'chapters/process-options.rst']

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'bootstrap'
html_logo = 'chapters/images/hvmi-logo-main-color.png'
html_use_index = True

if html_theme == 'bootstrap':
    html_theme_path = sphinx_bootstrap_theme.get_html_theme_path()
    html_theme_options = {
        'bootstrap_version': "3",
        'navbar_site_name': 'Chapters',
        'navbar_links': [
            ("GitHub", "https://github.com/hvmi/hvmi", True),
            ("Blog", "https://hvmi.github.io/blog/", True),
            ("Doxygen", "_static/doxygen/html/index"),
        ],
        'source_link_position': "footer",
    }

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']
master_doc = 'index'

# autosectionlabel settings
# True to prefix each section label with the name of the document it is in, followed by a colon. 
autosectionlabel_prefix_document = True

# Uncomment this to use custom.css
def setup(app):
    if html_theme == 'bootstrap':
        app.add_css_file('custom.css')
