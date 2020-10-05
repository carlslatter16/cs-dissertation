all: tor wordcount

tor:
	latexmk -pdf -quiet -latexoption=-shell-escape TermsOfReference

#dissertation:
#	latexmk -pdf -quiet -latexoption=-shell-escape /Diss/Dissertation

wordcount:
	texcount -total -inc TermsOfReference.tex
#	texcount -total -inc /Diss/Dissertation.tex
