<script>
$(function () {
    const form = 'nethubSettings';
    const endpoint = '/api/nethubagent/settings/';
    mapDataToFormUI({[form]: endpoint + 'get'});
    $('#saveNetHub').on('click', function () {
        saveFormToEndpoint(endpoint + 'set', form);
    });
});
</script>

<div class="col-md-12">
    {{ partial('layout_partials/base_form', ['fields': settingsForm, 'id': 'nethubSettings']) }}
    <button id="saveNetHub" class="btn btn-primary" type="button">{{ lang._('Save') }}</button>
</div>
