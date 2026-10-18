# OPNsense plugin development

This unsigned development skeleton provides Services → NetHub Agent and an Enable
preference. It does not enroll devices, start a tunnel, or install a service.
Saved model settings remain in config.xml after uninstall.

On the isolated OPNsense test guest, run `sh build.sh`, then install
`dist/os-nethub-agent.pkg` with `pkg add`. Build requirements are FreeBSD, pkg,
sha256, and Python 3.13. Python is a build tool here, not a new runtime service.
The builder validates version agreement, stages source files, and checks the
resulting package before publishing the local artifact. Release packaging and
signing remain separate from this development build.

Run `python -m pytest agents/opnsense/plugin/tests` from the repository root with
PHP and POSIX sh available. CI checks model/form/package structure, XML parsing,
PHP and shell syntax, and the text masks against configuration-injection inputs.
Device installation, native model validation, menu visibility, save, uninstall,
and reinstall still require the target guest.

Reference structures were inspected at opnsense/plugins
`a2a4b2de7aa343760f6d41c22152abf7a13f54ae` (helloworld) and
KKazuhaK/OPNsense-repo `b19db0c5b97fefa229b6a77c15107b4aac5177ef`
(os-easytier). NetHub files are independently written. No reference plugin source,
shared packaging files, or mirror scripts are incorporated.
