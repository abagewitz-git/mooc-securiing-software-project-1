from django.urls import path

from . import views

app_name = 'polls'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<int:pk>/', views.DetailView.as_view(), name='detail'),
    path('<int:pk>/results/', views.ResultsView.as_view(), name='results'),
    path('<int:question_id>/vote/', views.vote, name='vote'),
    path("trigger-error/", views.trigger_debug_error, name="trigger_error"),
    path("raw-search/", views.raw_search, name="raw_search"),
    path("all-results/", views.all_results, name="all_results"),
    path("import-from-url/", views.import_from_url, name="import_from_url"),
]
