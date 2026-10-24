<script>
$(function () {
    let circuitPending = false;
    const form = 'nethubSettings';
    const endpoint = '/api/nethubagent/settings/';
    mapDataToFormUI({[form]: endpoint + 'get'});
    function showEnrollment() {
        ajaxCall('/api/nethubagent/enroll/get', {}, function (result) {
            $('#enrollNetHub').prop('disabled', result.enrolled === true);
            $('#nethubEnrollmentInfo').text(result.enrolled ?
                '{{ lang._("Enrolled device") }}: ' + result.device_id + ' | ' + result.console_url :
                '{{ lang._("Not enrolled") }}');
        });
    }
    function showStatus() {
        ajaxCall('/api/nethubagent/service/status', {}, function (result) {
            $('#nethubStatus').text(JSON.stringify(result, null, 2));
            const known = result && typeof result.disabled === 'boolean';
            $('#nethubCircuitBreaker').prop('checked', known && result.disabled)
                .prop('disabled', circuitPending || !known);
            $('#nethubCircuitStatus').text(!known ? '{{ lang._("Circuit breaker status unavailable") }}' :
                result.disabled ? (result.status === 'stopped' ? '{{ lang._("Circuit breaker enabled; tunnel stopped") }}' :
                    '{{ lang._("Circuit breaker enabled; tunnel has not stopped. Check service status.") }}') :
                    '{{ lang._("Circuit breaker released; saved settings and other stop conditions still apply") }}');
        });
    }
    showStatus();
    showEnrollment();
    $('#nethubCircuitBreaker').on('change', function () {
        const action = this.checked ? 'disable' : 'enable';
        circuitPending = true;
        $(this).prop('disabled', true);
        $('#nethubCircuitResult').text('{{ lang._("Applying local circuit breaker…") }}');
        ajaxCall('/api/nethubagent/service/' + action, {}, function (result, status) {
            circuitPending = false;
            $('#nethubCircuitResult').text(status === 'success' && result && typeof result.message === 'string' ?
                result.message : '{{ lang._("Operation was not confirmed. Refresh status before retrying.") }}');
            showStatus();
        });
    });
    $('#saveNetHub').on('click', function () {
        saveFormToEndpoint(endpoint + 'set', form);
    });
    $('#enrollNetHub').on('click', function () {
        const button = $(this);
        const request = {origin: $('#nethubConsoleUrl').val(), token: $('#nethubEnrollToken').val()};
        button.prop('disabled', true);
        $('#nethubEnrollToken').val('');
        $('#nethubEnrollmentResult').text('{{ lang._("Requesting enrollment…") }}');
        ajaxCall('/api/nethubagent/enroll/enroll', request, function (result, status) {
            $('#nethubEnrollmentResult').text(status === 'success' && typeof result.message === 'string' ?
                result.message : '{{ lang._("Enrollment response unavailable. Check the console inventory before using another token.") }}');
            button.prop('disabled', result.enrolled === true);
            if (result.enrolled === true) {
                mapDataToFormUI({[form]: endpoint + 'get'});
                showEnrollment();
                showStatus();
            }
        });
    });
    $('#applyNetHub').on('click', function () {
        ajaxCall('/api/nethubagent/service/reconcile', {}, showStatus);
    });
    $('#refreshNetHub').on('click', function () {
        ajaxCall('/api/nethubagent/service/report', {}, showStatus);
    });
    $('#removeNetHub').on('click', function () {
        if (!window.confirm('{{ lang._("Stop the tunnel and remove this enrollment?") }}')) {
            return;
        }
        const button = $(this);
        button.prop('disabled', true);
        ajaxCall('/api/nethubagent/remove/remove', {}, function (result, status) {
            $('#nethubEnrollmentResult').text(status === 'success' && typeof result.message === 'string' ?
                result.message : '{{ lang._("Removal response unavailable. Check status before retrying.") }}');
            button.prop('disabled', false);
            showEnrollment();
            showStatus();
            mapDataToFormUI({[form]: endpoint + 'get'});
        });
    });
});
</script>

<div class="col-md-12">
    {{ partial('layout_partials/base_form', ['fields': settingsForm, 'id': 'nethubSettings']) }}
    <button id="saveNetHub" class="btn btn-primary" type="button">{{ lang._('Save') }}</button>
    <button id="applyNetHub" class="btn btn-default" type="button">{{ lang._('Apply') }}</button>
    <button id="refreshNetHub" class="btn btn-default" type="button">{{ lang._('Refresh status') }}</button>
    <h2>{{ lang._('Local circuit breaker') }}</h2>
    <label><input id="nethubCircuitBreaker" type="checkbox" disabled> {{ lang._('Stop remote access') }}</label>
    <p>{{ lang._('Stops the NetHub tunnel without changing saved configuration. Keep a local console or another independent access path before switching it on.') }}</p>
    <p id="nethubCircuitStatus" role="status"></p>
    <p id="nethubCircuitResult" role="status"></p>
    <pre id="nethubStatus"></pre>
    <h2>{{ lang._('Enrollment') }}</h2>
    <p id="nethubEnrollmentInfo"></p>
    <p>{{ lang._('Enter the HTTPS address of your NetHub console and its one-use token. Enrollment enables the tunnel. The router keeps its current GUI login and security checks.') }}</p>
    <p>{{ lang._('Before enrolling, confirm that you can reach this router without NetHub, such as through a local console or physical access.') }}</p>
    <div class="form-group">
        <label for="nethubConsoleUrl">{{ lang._('Console HTTPS address') }}</label>
        <input id="nethubConsoleUrl" class="form-control" type="url" maxlength="512" autocomplete="off" placeholder="https://console.example.com">
    </div>
    <div class="form-group">
        <label for="nethubEnrollToken">{{ lang._('Enrollment token') }}</label>
        <input id="nethubEnrollToken" class="form-control" type="password" maxlength="43" autocomplete="off" spellcheck="false">
    </div>
    <button id="enrollNetHub" class="btn btn-primary" type="button">{{ lang._('Enroll') }}</button>
    <button id="removeNetHub" class="btn btn-danger" type="button">{{ lang._('Remove enrollment') }}</button>
    <p id="nethubEnrollmentResult" role="status"></p>
</div>
