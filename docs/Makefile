# Minimal Sphinx Makefile

SPHINXOPTS  ?=
SPHINXBUILD ?= sphinx-build
SOURCEDIR    = .
BUILDDIR     = _build

.PHONY: help html clean livehtml fresh pdf fresh-pdf

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

html:
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

clean:
	@rm -rf "$(BUILDDIR)"

fresh-html:
	@cd .. && .venv/bin/pip install -e . -q
	@$(SPHINXBUILD) -aE "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS) $(O)

pdf:
	@$(SPHINXBUILD) -b latex "$(SOURCEDIR)" "$(BUILDDIR)/latex" $(SPHINXOPTS) $(O)
	@$(MAKE) -C "$(BUILDDIR)/latex" all-pdf

fresh-pdf:
	@rm -rf "$(BUILDDIR)/latex"
	@cd .. && .venv/bin/pip install -e . -q
	@$(SPHINXBUILD) -aE -b latex "$(SOURCEDIR)" "$(BUILDDIR)/latex" $(SPHINXOPTS) $(O)
	@$(MAKE) -C "$(BUILDDIR)/latex" all-pdf

livehtml:
	sphinx-autobuild "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS) $(O)
