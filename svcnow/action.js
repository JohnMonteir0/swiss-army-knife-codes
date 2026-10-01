function onChange(control, oldValue, newValue, isLoading) {
    if (isLoading) {
        return;
    }

    var allFields = [
        'billingMode',
        'readCapacity',
        'writeCapacity',

        'gsiAction',
        'gsiName',
        'partitionKey',
        'partitionKeyType',
        'sortKey',
        'sortKeyType',
        'projectionType',
        'nonKeyAttributes',

        'ttlEnabled',
        'ttlAttribute',

        'tagKey',
        'tagValue',

        'capacityType',
        'minCapacity',
        'maxCapacity',
        'targetValue',
        'scaleInCooldown',
        'scaleOutCooldown'
    ];

    // Reset all dynamic fields
    for (var i = 0; i < allFields.length; i++) {
        g_form.setMandatory(allFields[i], false);
        g_form.setDisplay(allFields[i], false);
    }

    switch (newValue) {

        case 'changeCapacity':
            showRequired('readCapacity');
            showRequired('writeCapacity');
            break;

        case 'changeBillingMode':
            showRequired('billingMode');
            break;

        case 'manageGsi':
            showRequired('gsiAction');
            showRequired('gsiName');
            break;

        case 'manageTags':
            showRequired('tagKey');
            showRequired('tagValue');
            break;

        case 'configureTtl':
            showRequired('ttlEnabled');
            break;

        case 'configureAutoscaling':
            showRequired('capacityType');
            showRequired('minCapacity');
            showRequired('maxCapacity');
            showRequired('targetValue');

            showOptional('scaleInCooldown');
            showOptional('scaleOutCooldown');
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