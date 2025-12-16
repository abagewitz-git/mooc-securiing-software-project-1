LINK to gitrepo: https://github.com/abagewitz-git/mooc-securiing-software-project-1    
The example uses the djangotutorial that is modified to exeplify 5 OWASP examples from this list: https://owasp.org/www-project-top-ten/. 
The example uses standard python and should not need any specific installations. 

Happy reviewing! 

/Anders

------------------------------------------------------------------------------------------------------------------------------
FLAW 1: A05 - Security Misconfiguration https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/
    Source code link:
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/mysite/settings.py#L26   -- Debug=True   
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L71       -- view to trigger runtimeerror
    Description
        Flaw 1 demonstrates that one should never run a production application with debug = true. When using this settings the application will provide a full stacktrace if it encounters an error. 
        The stacktrace will reveal a lot of internatal information to the user. This information could then be used to attack the application . 
        To force an error in my example I have constructed a simple view trigger_debug_error that raises a runtimeerror.
        Access the view by going to URL http://127.0.0.1:8000/polls/trigger-error/
        When Debug=True in settings.py this gives a full stacktrace and other information.
    How to fix
        Set Debug=false in settings.py      https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/mysite/settings.py#L26


------------------------------------------------------------------------------------------------------------------------------
FLAW 2: A01/A05 - Cross-Site Request Forgery (CSRF)
    Source code link:
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L17                    -- import of django.views.decorators.csrf import csrf_exempt to be able to do csrf_exempt
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L51                    -- @csrf_exempt on vote (accepts POST without token)
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/detail.html#L7  -- csrf_token removed from form
    Description
        Althoug CSRF is not on the OWASP top-10 is was stated in the assignement that it was allowed as a valid flaw. By not using CSRF one opens up for an attacker to post from external sources and this could be harmful. 
        CSRF protection is disabled on the vote endpoint and the form omits the CSRF token, so any site can post votes.
        Demo: with server running, submit POST without token:
              curl -v -X POST -d "choice=11" http://127.0.0.1:8000/polls/2/vote/
              (adjust choice id for the target question). The vote is accepted, no 403.
    How to fix
        Remove @csrf_exempt from vote in views.py (and remove import)   https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L51
        Restore {% csrf_token %} in the detail.html form                https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/detail.html#L7


------------------------------------------------------------------------------------------------------------------------------
FLAW 3: A03 - Injection (raw SQL search) https://owasp.org/Top10/2021/A03_2021-Injection/
    Source code link:
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L81                        -- raw_search uses f-string SQL with user input
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/raw_search.html#L1  -- displays query and results
    Description
        To demonstrate SQL-injection I have implemented a search (raw_search) with functionality to search for questions. 
        The view builds SQL with unsanitized query parameter q and executes it directly and is therefore extremly harmful. 
        The user can inject various forms of SQL that can reveal a lot of information. 
        I demonstrate this by entering the below SQL in the searchfiels. 
            %' UNION SELECT id, 'username: ' || username || ' email: ' || email || ' pwd: ' || password AS userpwd FROM auth_user  --
        This will not only list all questions in the database but will fill ALSO display all the applications users ID, Email and encryptet pwd (pwd is encrypted though) 
    How to fix
        Use ORM filtering (Question.objects.filter(question_text__icontains=q)) or parametrized SQL (cursor.execute(..., [f\"%{q}%\"])) instead of string concatenation. 
            https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L99 


------------------------------------------------------------------------------------------------------------------------------
FLAW 4: A01 - Broken Access Control (unprotected admin-like report)
    Source code link:
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L115                       -- all_results view
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/all_results.html#L1 -- admin-like report template
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/models.py#L11                       -- custom permission view_admin_report
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/index.html#L16      -- link shown only when authenticated
    Description
        This is an example of how a view should be protected with permission but isnt. The view all-results lists all questions and choices for an "admin"
        An admin-like report lists all questions, choices, vote counts and publish dates, initially without authentication. 
        Demo: visit http://127.0.0.1:8000/polls/all-results/ as anonymous and see full data exposure.
    How to fix
        Add access control: 
            define custom permission (polls.view_admin_report), this is done in models.py for the Question class 
            decorate the all results view with @login_required and @permission_required https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L112-L115  
            A link to the all_results page is displayed on index.html if the user is logged in and hide the link unless authenticated/authorized.  
                https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/index.html#L16
            After migrating permissions and assigning them, anonymous/unauthorized users are blocked.
            To view the page after access control is added the user need to be logged in and have the permission  ("view_admin_report", "Can view admin report")

------------------------------------------------------------------------------------------------------------------------------
FLAW 5: A10 - Server-Side Request Forgery (SSRF)
    Source code link:
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L126                           -- import_from_url view fetches arbitrary URL
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/templates/polls/import_from_url.html#L1 -- form to submit target URL
        https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/urls.py#L14                             -- route /polls/import-from-url/
    Description
        This is an fictional example of implementation of a feature that fetches data from a remote URL to "upload" questions and choices from an external source to add to the polling application.
        The functionality is to create questions and choices is not implemented, it's purely used as an exemple that could use import from external sources. Maybe not a good idea though...
        A server-side fetch imports content from any URL a user provides, with hardening checks or validation .
        Demo: http://127.0.0.1:8000/polls/import-from-url/?url=http://127.0.0.1:8000/admin/ (server fetches internal admin page)

    How to fix
        Example of hardning is written in https://github.com/abagewitz-git/mooc-securiing-software-project-1/blob/main/djangotutorial/polls/views.py#L144-L185
        Enforce allowlist/blocklist (no localhost/private IPs)
        Allow only http/https
        Allow only .JSON
        disable redirects
        set short timeouts and max response size
        Actually the best way to fix this would probably be to remove server-side fetch entirely, instead implement file upload (also with checks), but that would not be a fun fix i think. 

------------------------------------------------------------------------------------------------------------------------------
