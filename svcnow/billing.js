function onChange(control, oldValue, newValue, isLoading) {
    if (isLoading) {
        return;
    }

    var isProvisioned = newValue === 'PROVISIONED';

    g_form.setDisplay('readCapacity', isProvisioned);
    g_form.setDisplay('writeCapacity', isProvisioned);

    g_form.setMandatory('readCapacity', isProvisioned);
    g_form.setMandatory('writeCapacity', isProvisioned);

    if (!isProvisioned) {
        g_form.clearValue('readCapacity');
        g_form.clearValue('writeCapacity');
    }
}