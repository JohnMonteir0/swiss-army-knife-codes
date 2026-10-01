function onChange(control, oldValue, newValue, isLoading) {
    if (isLoading) {
        return;
    }

    var isInclude = newValue === 'INCLUDE';

    g_form.setDisplay('nonKeyAttributes', isInclude);
    g_form.setMandatory('nonKeyAttributes', isInclude);

    if (!isInclude) {
        g_form.clearValue('nonKeyAttributes');
    }
}