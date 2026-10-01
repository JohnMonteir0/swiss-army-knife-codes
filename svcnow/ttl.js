function onChange(control, oldValue, newValue, isLoading) {
    if (isLoading) {
        return;
    }

    var isEnabled = newValue === 'true';

    g_form.setDisplay('ttlAttribute', isEnabled);
    g_form.setMandatory('ttlAttribute', isEnabled);

    if (!isEnabled) {
        g_form.clearValue('ttlAttribute');
    }
}