# Camera capture failure during MOV image acceptance — 2026-10-15

Initial hardware acceptance of image **`20261015T121728Z-e664cb9647e7` failed**.
Subsequent [recovery validation](ffmpeg-mov-deployment-validation-2026-10-15.md)
passed fresh capture checks, three reboots and user-confirmed video/Hailo.
At the initial failure, login worked but video and Hailo processing did not.
No successful deployment report was issued at that point.

## Confirmed observations

- The earlier installed-file, system-FFmpeg, service-start and three-reboot
  checks passed their limited assertions. They did **not** establish successful
  camera capture or Hailo inference. The required user UI confirmation failed.
- The same camera service remained active without systemd restarts. Its
  `camera pipeline running` message was followed about one second later by
  `Camera frontend has timed out!` and a V4L2 dequeue timeout. The immediately
  preceding reboot has the same error. This is not a login failure.
- Camera frontend (`rp1-cfe`) and ISP (`pispbe`) interrupt counters were both
  zero after hours of uptime. The sensor was detected and the media topology
  configured, but no capture progress was observed.
- With the application stopped, independent installed `rpicam-vid` raw-YUV
  captures at 1920×1080/30fps and 640×480/15fps both produced no frame metadata
  and repeated the frontend timeout. Each bounded test ended at its 12-second
  alarm. The application was restored and temporary files removed afterwards.
  The symptom therefore also occurs outside the application and Hailo pipeline.
- The previous user-accepted image and this image have identical camera
  application, libcamera, PiSP/IPA, kernel/module and selected four boot-file
  hashes. The protected-file changes are libavutil, libavformat, and the
  separately verified generated-data changes in librpicam_app. These facts
  narrow the investigation; they do not prove a defective cable or rule out
  every software/environmental cause.

## Validation gap

Service activity and a startup log were insufficient acceptance criteria. The
automated checks did not reject the later userspace capture timeout and did
not measure ongoing capture. Their historical results are retained with their
limited scope; they must not be represented as successful video/AI acceptance.
The original acceptance record retains the user's functional failure.

A follow-up diagnostic checks live frontend/ISP counter growth over five
seconds and capture-timeout/requeue errors for the current application PID.
It subsequently passed on the recovered boot and each of three new reboots.
Hardware progress is still not a substitute for authenticated video and
inference confirmation.

## Recovery experiment and result

The user authorized normal shutdown for a complete power removal/reconnection;
the initial plan was to leave the camera cable unchanged.
`systemctl poweroff` returned success and SSH disconnected. The user subsequently
reported a new boot and suspected loose camera connection.
Capture resumed without software changes. Since cable inspection and power
cycling were not isolated, the individual cause is not proven; the evidence
supports a connection/device-state cause. Fresh successful checks are linked above.

No package, image, account, authentication or camera configuration was changed.
No further image build or QEMU work was performed. Hailo inference was
subsequently confirmed by the user, with increasing frames and detections.
No separate Hailo hardware fault was established.

Working evidence: `.state/video-ai-stall-2026-10-15/` and the failed user
confirmation in `.state/ffmpeg-mov-deployment-2026-10-15/`. These paths are
Git-excluded. Operational log filtering runs on the device before transfer;
authentication/session logs and credentials are not collected.
