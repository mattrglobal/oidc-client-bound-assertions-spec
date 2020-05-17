# Convert markdown to XML and HTML versions
docker run -v `pwd`:/data danielfett/markdown2rfc spec.md

# Delete XML version
rm client-bound-end-user-assertion.xml

# Rename the HTML version for hosting with GH pages
mv client-bound-end-user-assertion.html index.html