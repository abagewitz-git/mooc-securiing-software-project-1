LINK to gitrepo: https://github.com/abagewitz-git/mooc-securiing-software-project-1.git


OBS OBS OBS, fixa alla länkar till filer efter uppladdning till GIT

------------------------------------------------------------------------------------------------------------------------------
FLAW 1: A05 - Security Misconfiguration https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/
    Source code link:
        djangotutorial/mysite/settings.py:26   -- Debug=True
        djangotutorial/polls/views.py:58       -- view to trigger runtimeerror
    Description
        Never run a production application with debug = true.
        To force an error in my example I have constructed a simple view trigger_debug_error that raises a runtimeerror.
        Access the view by going to URL http://127.0.0.1:8000/polls/trigger-error/
        When Debug=True in settings.py this gives a full stacktrace and other information.
    How to fix
        Set Debug=false in settings.py      djangotutorial/mysite/settings.py:26


------------------------------------------------------------------------------------------------------------------------------
FLAW 2: A01/A05 - Cross-Site Request Forgery (CSRF)
    Source code link:
        djangotutorial/polls/views.py:8                     -- import of django.views.decorators.csrf import csrf_exempt to be able to do csrf_exempt
        djangotutorial/polls/views.py:51                    -- @csrf_exempt on vote (accepts POST without token)
        djangotutorial/polls/templates/polls/detail.html:7  -- csrf_token removed from form
    Description
        CSRF protection is disabled on the vote endpoint and the form omits the CSRF token, so any site can post votes.
        Demo: with server running, submit POST without token:
              curl -v -X POST -d "choice=11" http://127.0.0.1:8000/polls/2/vote/
              (adjust choice id for the target question). The vote is accepted, no 403.
    How to fix
        Remove @csrf_exempt from vote in views.py (and remove import)   djangotutorial/polls/views.py:51
        Restore {% csrf_token %} in the detail.html form                djangotutorial/polls/templates/polls/detail.html:7


------------------------------------------------------------------------------------------------------------------------------
FLAW 3: A03 - Injection (raw SQL search) https://owasp.org/Top10/2021/A03_2021-Injection/
    Source code link:
        djangotutorial/polls/views.py:73                        -- raw_search uses f-string SQL with user input
        djangotutorial/polls/templates/polls/raw_search.html:1  -- displays query and results
    Description
        The raw_search view builds SQL with unsanitized query parameter q and executes it directly.
        Demo: http://127.0.0.1:8000/polls/raw-search/?q=%' OR 1=1 --
        This returns all rows and shows how injection could be used; 
        %' UNION SELECT id, 'username: ' || username || ' email: ' || email || ' pwd: ' || password AS userpwd FROM auth_user  --
        This will list all questions in the database PLUS ID, Email and encryptet pwd of all users in the DB
    How to fix
        Use ORM filtering (Question.objects.filter(question_text__icontains=q)) or parametrized SQL (cursor.execute(..., [f\"%{q}%\"])) instead of string concatenation. 
        djangotutorial/polls/views.py:98 


------------------------------------------------------------------------------------------------------------------------------
FLAW 4: A01 - Broken Access Control (unprotected admin-like report)
    Source code link:
        djangotutorial/polls/views.py:101                       -- all_results view
        djangotutorial/polls/templates/polls/all_results.html:1 -- admin-like report template
        djangotutorial/polls/models.py:12                       -- custom permission view_admin_report
        djangotutorial/polls/templates/polls/index.html:14      -- link shown only when authenticated
    Description
        This is an example of how a view should be protected with permission but isnt. The view all-results lists all questions and choices for an "admin"
        An admin-like report lists all questions, choices, vote counts and publish dates, initially without authentication. 
        Demo: visit http://127.0.0.1:8000/polls/all-results/ as anonymous and see full data exposure.
    How to fix
        Add access control: 
            define custom permission (polls.view_admin_report), this is done in models.py for the Question class 
            decorate the all results view with @login_required and @permission_required djangotutorial/polls/views.py:113  
            A link to the all_results page is displayed on index.html if the user is logged in and hide the link unless authenticated/authorized.  djangotutorial/polls/templates/polls/index.html:14
            After migrating permissions and assigning them, anonymous/unauthorized users are blocked.
            To view the page after access control is added the user need to be logged in and have the permission  ("view_admin_report", "Can view admin report")

------------------------------------------------------------------------------------------------------------------------------
FLAW 5: A10 - Server-Side Request Forgery (SSRF)
    Source code link:
        djangotutorial/polls/views.py:126                           -- import_from_url view fetches arbitrary URL
        djangotutorial/polls/templates/polls/import_from_url.html:1 -- form to submit target URL
        djangotutorial/polls/urls.py:14                             -- route /polls/import-from-url/
    Description
        This is an fictional example of implementation of a feature that fetches data from a remote URL to "upload" questions and choices from an external source to add to the polling application.
        The functionality is to create questions and choices is not implemented, it's purely used as an exemple that could use import from external sources. Maybe not a good idea though...
        A server-side fetch imports content from any URL a user provides, with hardening checks or validation .
        Demo: http://127.0.0.1:8000/polls/import-from-url/?url=http://127.0.0.1:8000/admin/ (server fetches internal admin page)

    How to fix
        Example of hardning is written in djangotutorial/polls/views.py:144 to 185
        Enforce allowlist/blocklist (no localhost/private IPs)
        Allow only http/https
        Allow only .JSON
        disable redirects
        set short timeouts and max response size
        Actually the best way to fix this would probably be to remove server-side fetch entirely, instead implement file upload (also with checks), but that would not be a fun fix i think. 

------------------------------------------------------------------------------------------------------------------------------
