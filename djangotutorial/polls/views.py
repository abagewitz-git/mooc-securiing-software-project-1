from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import generic
from django.utils import timezone
from django.db import connection
from django.db.models import Prefetch
# FLAW4 access control decorators (used to secure admin-like report)
from django.contrib.auth.decorators import login_required, permission_required
import urllib.request
import urllib.parse
import socket
import ipaddress
import json

# CSRF exemption for demonstration purposes for FLAW2   
from django.views.decorators.csrf import csrf_exempt

from .models import Choice, Question


class IndexView(generic.ListView):
    template_name = 'polls/index.html'
    context_object_name = 'latest_question_list'

    def get_queryset(self):
        """
        Return the last five published questions (not including those set to be
        published in the future).
        """
        return Question.objects.filter(pub_date__lte=timezone.now()).order_by("-pub_date")[
            :5
        ]


class DetailView(generic.DetailView):
    model = Question
    template_name = 'polls/detail.html'
    def get_queryset(self):
        """
        Excludes any questions that aren't published yet.
        """
        return Question.objects.filter(pub_date__lte=timezone.now())


class ResultsView(generic.DetailView):
    model = Question
    template_name = 'polls/results.html'


@csrf_exempt  # CSRF disabled intentionally for demo of FLAW2 (unsafe). Comment out to enbable csrf protection.
def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the question voting form.
        return render(request, 'polls/detail.html', {
            'question': question,
            'error_message': "You didn't select a choice.",
        })
    else:
        selected_choice.votes += 1
        selected_choice.save()
        # Always return an HttpResponseRedirect after successfully dealing
        # with POST data. This prevents data from being posted twice if a
        # user hits the Back button.
        return HttpResponseRedirect(reverse('polls:results', args=(question.id,)))


def trigger_debug_error(request):
    """
    View used to demonstrate FLAW1: Deliberately raises an exception to demonstrate debug stack traces when DEBUG=True. 
    When DEBUG is set to True in settings.py, accessing this view will display a detailed debug stack trace.  
    This can expose sensitive information about the application's internals, which is a security risk.
    When debug mode is disabled (DEBUG=False), a generic error page is shown instead, preventing information leakage.      
    """
    raise RuntimeError("Demo FLAW1: With Debug=True in settings.py the application will leak internal info (Security Misconfiguration A05)")


def raw_search(request):
    """
    FLAW 3 (A03 Injection): vulnerable raw SQL search using unsanitized user input in the query string (?q=).
    """
    q = request.GET.get("q", "")
    results = []
    if q:
        
        #------------------------------------------------------------------------------------------------------------------
        # Vulnerable code: user input is concatenated directly into SQL query wichh can lead to SQL Injection attacks
        #------------------------------------------------------------------------------------------------------------------
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT id, question_text FROM polls_question WHERE question_text LIKE '%{q}%'"
            )
            results = cursor.fetchall()
        
        #------------------------------------------------------------------------------------------------------------------
        # Secure alternatives (uncomment the lines below to fix):
        #------------------------------------------------------------------------------------------------------------------
        # results = Question.objects.filter(question_text__icontains=q)
        # with connection.cursor() as cursor:
        #     cursor.execute(
        #         "SELECT id, question_text FROM polls_question WHERE question_text LIKE %s",
        #         [f"%{q}%"],
        #     )
        #     results = cursor.fetchall()

    return render(request, "polls/raw_search.html", {"results": results, "q": q})


# FLAW4 enforced access control for the admin-like report
#@login_required
#@permission_required('polls.view_admin_report', raise_exception=True)
def all_results(request):
    """
    FLAW 4 (A01 Broken Access Control): exposes an admin-like report of all questions,
    choices and vote counts without any authentication check.
    """
    questions = Question.objects.prefetch_related(
        Prefetch("choice_set", queryset=Choice.objects.order_by("id"))
    ).order_by("id")
    return render(request, "polls/all_results.html", {"questions": questions})


def import_from_url(request):
    """
    FLAW 5 (A10 SSRF): fetches arbitrary URL provided by user without allowlist or host validation.
    """
    target = request.GET.get("url", "")
    content = None
    error = None
    if target:
        try:
            parsed = urllib.parse.urlparse(target)
            #----------------------------------------------------------------
            # Unsafe fetch (demo): no allowlist/IP checks, no redirect block,
            # no content-type validation. This is intentionally vulnerable.
            #----------------------------------------------------------------
            with urllib.request.urlopen(target, timeout=3) as resp:
                content = resp.read(2000).decode("utf-8", errors="replace") 


            #----------------------------------------------------------------------------
            # FLAW5 Secure checks to mitigate SSRF risks:
            #----------------------------------------------------------------------------

            # Allow only HTTP(S) schemes
            #if parsed.scheme not in {"http", "https"}:
            #    raise ValueError("Blocked: only http/https allowed")
            
            # Require a hostname in the URL
            #if not parsed.hostname:
            #    raise ValueError("Blocked: no hostname")
            
            # Resolve and block private/loopback/link-local IPs to prevent internal access
            #ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
            #if ip.is_private or ip.is_loopback or ip.is_link_local:
            #    raise ValueError("Blocked private/loopback address")

            # Allowlist: only fetch from explicitly trusted hosts (adjust as needed)
            #allowed_hosts = {"example.com", "api.example.com", "jsonplaceholder.typicode.com"}
            #if parsed.hostname not in allowed_hosts:
            #    raise ValueError("Blocked by allowlist")

            # Build request without following redirects (block 3xx)
            #class NoRedirect(urllib.request.HTTPRedirectHandler):
            #    def redirect_request(self, req, fp, code, msg, headers, newurl):
            #        return None
            #opener = urllib.request.build_opener(NoRedirect)
            #req = urllib.request.Request(target, headers={"Accept": "application/json"})
            #with opener.open(req, timeout=3) as resp:
            #   status = getattr(resp, "status", resp.getcode())
            #    if 300 <= status < 400:
            #        raise ValueError(f"Blocked redirect status {status}")
            #    # Require JSON content type
            #    ctype = resp.headers.get("Content-Type", "")
            #    if not ctype.lower().startswith("application/json"):
            #        raise ValueError(f"Blocked: non-JSON content type ({ctype})")
            #    # Limit how much we read to avoid huge responses
            #    raw = resp.read(2000).decode("utf-8", errors="replace")
                # Validate JSON (will raise if invalid)
            #    parsed_json = json.loads(raw)
                # Pretty-print for display
            #    content = json.dumps(parsed_json, indent=2, ensure_ascii=False)


        except Exception as exc:
            error = str(exc)

    return render(
        request,
        "polls/import_from_url.html",
        {"target": target, "content": content, "error": error},
    )
