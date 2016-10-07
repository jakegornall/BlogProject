This blog is for the project, Multi User Blog, on Udacity. 
Meant for use on Google App Engine. Utilizes Python, Jinja2, HTML5, and CSS. 
This site is a multi-user blog where users can sign up, sign in, create/edit/delete posts, comment on posts, edit/delete comments,
like/unlike posts. 

To run on local host:

1. Clone this repository to your machine.
2. Open Google App Engine Launcher (if you don't have it, download it at: https://cloud.google.com/appengine/docs/python/download)
3. Go to File > Add Existing Application...
4. Enter the path to the directory that contains the repository.
5. Take note of which port will host the site. (defaults to Port: 8080)
6. Click "Add".
7. Select your directory and click "Run".
8. Before opening in your browser, open main.py and change the global variable hostURL to "http://localhost:(your port from step 5)"

To see deployed site visit: 
http://www.blogproject-144722.appspot.com

NOTE: To view current database entities while running on localhost use the provided admin port followed by /datastore. (ex. http://localhost:8000/datastore)


