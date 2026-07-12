from apps.profile_service.serializers import UserProfileSerializer
from apps.profile_service.views import ProfileMeView


ProfileMeView.serializer_class = UserProfileSerializer
