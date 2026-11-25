// TEST ONLY. Never install fixture policies into the OS or runtime.
permit (
    principal is Symbi::Principal,
    action == Symbi::Action::"model.invoke",
    resource is Symbi::Model
)
when {
    context.session_class == "public" &&
    resource.location == "local" &&
    resource.provider == "fixture" &&
    resource.jurisdiction == "on-device" &&
    resource.cost == 0
};
