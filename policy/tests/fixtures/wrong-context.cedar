// TEST ONLY: session_class is a String, so this comparison must fail validation.
permit (
    principal is Symbi::Principal,
    action == Symbi::Action::"model.invoke",
    resource is Symbi::Model
)
when { context.session_class == 42 };
