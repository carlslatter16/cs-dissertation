all: dissertation wordcount

#tor:
#	latexmk -pdf -quiet -latexoption=-shell-escape /TOR/TermsOfReference

dissertation:
	latexmk -pdf -quiet -latexoption=-shell-escape Dissertation

wordcount:
#	texcount -total -inc /TOR/TermsOfReference.tex
	texcount -total -inc Dissertation.tex
