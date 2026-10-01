function onSubmit() {
    var action = g_form.getValue('action');

    if (action !== 'configureAutoscaling') {
        return true;
    }

    var minCapacity = parseInt(
        g_form.getValue('minCapacity'),
        10
    );

    var maxCapacity = parseInt(
        g_form.getValue('maxCapacity'),
        10
    );

    var targetValue = parseFloat(
        g_form.getValue('targetValue')
    );

    if (isNaN(minCapacity) || isNaN(maxCapacity)) {
        g_form.addErrorMessage(
            'Minimum and maximum capacity must be valid numbers.'
        );
        return false;
    }

    if (minCapacity < 1) {
        g_form.addErrorMessage(
            'Minimum capacity must be greater than zero.'
        );
        return false;
    }

    if (minCapacity > maxCapacity) {
        g_form.addErrorMessage(
            'Minimum capacity cannot be greater than maximum capacity.'
        );
        return false;
    }

    if (
        isNaN(targetValue) ||
        targetValue <= 0 ||
        targetValue > 100
    ) {
        g_form.addErrorMessage(
            'Target utilization must be between 1 and 100.'
        );
        return false;
    }

    return true;
}