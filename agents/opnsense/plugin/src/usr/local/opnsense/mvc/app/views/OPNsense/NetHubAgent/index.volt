<script>
$(function () {
    const form = 'nethubSettings';
    const endpoint = '/api/nethubagent/settings/';
    mapDataToFormUI({[form]: endpoint + 'get'});
    mapDataToFormUI({'nethubDebug': endpoint + 'debugGet'});
    function showStatus() {
        ajaxCall('/api/nethubagent/service/status', {}, function (result) {
            $('#nethubStatus').text(JSON.stringify(result, null, 2));
        });
    }
    showStatus();
    $('#saveNetHub').on('click', function () {
        saveFormToEndpoint(endpoint + 'set', form);
    });
    $('#saveNetHubDebug').on('click', function () {
        saveFormToEndpoint(endpoint + 'debugSet', 'nethubDebug');
    });
    $('#applyNetHub').on('click', function () {
        ajaxCall('/api/nethubagent/service/reconcile', {}, showStatus);
    });
    $('#refreshNetHub').on('click', showStatus);
});
</script>

<div class="col-md-12">
    {{ partial('layout_partials/base_form', ['fields': settingsForm, 'id': 'nethubSettings']) }}
    <button id="saveNetHub" class="btn btn-primary" type="button">{{ lang._('Save') }}</button>
    <button id="applyNetHub" class="btn btn-default" type="button">{{ lang._('Apply') }}</button>
    <button id="refreshNetHub" class="btn btn-default" type="button">{{ lang._('Refresh status') }}</button>
    <pre id="nethubStatus"></pre>
    <details>
        <summary>{{ lang._('Advanced (W2 debug only)') }}</summary>
        <p>{{ lang._('The relay CA must be provisioned locally before starting. This debug section will be removed or made read-only when enrollment is implemented.') }}</p>
        {{ partial('layout_partials/base_form', ['fields': debugForm, 'id': 'nethubDebug']) }}
        <button id="saveNetHubDebug" class="btn btn-default" type="button">{{ lang._('Save debug settings') }}</button>
    </details>
</div>
