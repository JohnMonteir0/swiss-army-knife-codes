function onChange(control, oldValue, newValue, isLoading) {
    if (isLoading) {
        return;
    }

    var gsiFields = [
        'partitionKey',
        'partitionKeyType',
        'sortKey',
        'sortKeyType',
        'projectionType',
        'nonKeyAttributes',
        'readCapacity',
        'writeCapacity'
    ];

    // Reset GSI-specific fields
    for (var i = 0; i < gsiFields.length; i++) {
        g_form.setMandatory(gsiFields[i], false);
        g_form.setDisplay(gsiFields[i], false);
    }

    switch (newValue) {

        case 'create':
            showRequired('partitionKey');
            showRequired('partitionKeyType');

            showOptional('sortKey');
            showOptional('sortKeyType');

            showRequired('projectionType');

            showOptional('readCapacity');
            showOptional('writeCapacity');
            break;

        case 'update':
            showRequired('readCapacity');
            showRequired('writeCapacity');
            break;

        case 'delete':
            // Only gsiName is required.
            break;
    }

    function showRequired(fieldName) {
        g_form.setDisplay(fieldName, true);
        g_form.setMandatory(fieldName, true);
    }

    function showOptional(fieldName) {
        g_form.setDisplay(fieldName, true);
        g_form.setMandatory(fieldName, false);
    }
}