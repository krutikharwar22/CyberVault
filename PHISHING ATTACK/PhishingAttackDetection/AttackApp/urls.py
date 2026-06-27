from django.urls import path
from AttackApp import views

app_name = 'AttackApp'

urlpatterns = [
    # Auth
    path('login/',    views.login_view,    name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/',   views.logout_view,   name='logout'),

    # Dashboard
    path('dashboard/',          views.dashboard,      name='dashboard'),
    path('api/dashboard-data/', views.dashboard_data, name='dashboard_data'),
    path('api/run-scan/',       views.run_scan,       name='run_scan'),
    path('api/block-ip/',       views.block_ip,       name='block_ip'),
    path('api/report-ip/',      views.report_ip,      name='report_ip'),
    path('api/view-report/',    views.view_report,    name='view_report'),
    path('api/predict-url/',    views.predict_url_api, name='predict_url_api'),
    path('api/notifications/', views.notifications_api, name='notifications_api'),
    path('api/notifications/mark-read/', views.notifications_mark_read, name='notifications_mark_read'),
    path('profile/', views.profile_view, name='profile'),
    path('scan/', views.scan_view, name='scan'),
    path('history/', views.history_view, name='history'),
    path('history/delete/<int:scan_id>/', views.delete_scan_result, name='delete_scan_result'),
    path('history/clear/', views.clear_my_history, name='clear_my_history'),
    path('settings/', views.settings_view, name='settings'),
    path('settings/export-scan-history.csv', views.export_scan_history_csv, name='export_scan_history_csv'),
    path('logs/', views.logs_view, name='logs'),

    # Staff console (not Django admin — avoids clashing with path('admin/', ...))
    path('staff/users/', views.admin_users_view, name='admin_users'),
    path('staff/users/toggle/', views.admin_user_toggle_active, name='admin_user_toggle'),
    path('staff/security/', views.admin_security_view, name='admin_security'),
    path('staff/security/block/', views.admin_block_ip_form, name='admin_block_ip_form'),
    path('staff/security/report/', views.admin_report_ip_form, name='admin_report_ip_form'),
    path('staff/security/unblock/', views.admin_unblock_ip, name='admin_unblock_ip'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
path('verify-otp/',      views.verify_otp_view,      name='verify_otp'),
path('reset-password/',  views.reset_password_view,  name='reset_password'),
]
