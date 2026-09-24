import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/pages/desktop_home_page.dart';
import 'package:flutter_hbb/desktop/pages/desktop_setting_page.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:window_manager/window_manager.dart';
// import 'package:flutter/services.dart';

import '../../common/shared_state.dart';

class DesktopTabPage extends StatefulWidget {
  const DesktopTabPage({Key? key}) : super(key: key);

  @override
  State<DesktopTabPage> createState() => _DesktopTabPageState();

  static void onAddSetting(
      {SettingsTabKey initialPage = SettingsTabKey.general}) {
    try {
      DesktopTabController tabController = Get.find<DesktopTabController>();
      tabController.add(TabInfo(
          key: kTabLabelSettingPage,
          label: kTabLabelSettingPage,
          selectedIcon: Icons.build_sharp,
          unselectedIcon: Icons.build_outlined,
          page: DesktopSettingPage(
            key: const ValueKey(kTabLabelSettingPage),
            initialTabkey: initialPage,
          )));
    } catch (e) {
      debugPrintStack(label: '$e');
    }
  }
}

class _DesktopTabPageState extends State<DesktopTabPage> {
  final tabController = DesktopTabController(tabType: DesktopTabType.main);

  _DesktopTabPageState() {
    RemoteCountState.init();
    Get.put<DesktopTabController>(tabController);
    tabController.add(TabInfo(
        key: kTabLabelHomePage,
        label: kTabLabelHomePage,
        selectedIcon: Icons.home_sharp,
        unselectedIcon: Icons.home_outlined,
        closable: false,
        page: DesktopHomePage(
          key: const ValueKey(kTabLabelHomePage),
        )));
    if (bind.isIncomingOnly()) {
      tabController.onSelected = (key) {
        if (key == kTabLabelHomePage) {
          windowManager.setSize(getIncomingOnlyHomeSize());
          setResizable(false);
        } else {
          windowManager.setSize(getIncomingOnlySettingsSize());
          setResizable(true);
        }
      };
    }
  }

  @override
  void initState() {
    super.initState();
    // HardwareKeyboard.instance.addHandler(_handleKeyEvent);
  }

  /*
  bool _handleKeyEvent(KeyEvent event) {
    if (!mouseIn && event is KeyDownEvent) {
      print('key down: ${event.logicalKey}');
      shouldBeBlocked(_block, canBeBlocked);
    }
    return false; // allow it to propagate
  }
  */

  @override
  void dispose() {
    // HardwareKeyboard.instance.removeHandler(_handleKeyEvent);
    Get.delete<DesktopTabController>();

    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final tabWidget = Container(
        padding: const EdgeInsets.all(2),
        decoration: BoxDecoration(
          color: MyTheme.accent,
          borderRadius: BorderRadius.circular(14),
        ),
        clipBehavior: Clip.antiAlias,
        child: CustomPaint(
          foregroundPainter: _ProtorkFramePainter(),
          child: Scaffold(
            backgroundColor: Theme.of(context).colorScheme.background,
            body: DesktopTab(
              controller: tabController,
              showTitle: true,
              tail: Offstage(
                offstage: bind.isIncomingOnly() || bind.isDisableSettings(),
                child: ActionIcon(
                  message: 'Settings',
                  icon: IconFont.menu,
                  onTap: DesktopTabPage.onAddSetting,
                  isClose: false,
                ),
              ),
            ))));
    return isMacOS || kUseCompatibleUiMode
        ? tabWidget
        : Obx(
            () => DragToResizeArea(
              resizeEdgeSize: stateGlobal.resizeEdgeSize.value,
              enableResizeEdges: windowManagerEnableResizeEdges,
              child: tabWidget,
            ),
          );
  }
}

/// Decorative strokes never intercept window controls or connection input.
class _ProtorkFramePainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final gold = Paint()
      ..color = MyTheme.accent
      ..strokeWidth = 1.2
      ..style = PaintingStyle.stroke;
    final headerWidth = (size.width * 0.33).clamp(180.0, 310.0);
    final header = Path()
      ..moveTo(0, 39)
      ..lineTo(headerWidth - 32, 39)
      ..lineTo(headerWidth - 10, 17)
      ..lineTo(headerWidth + 18, 17);
    canvas.drawPath(header, gold);
    final sidebar = (size.width * 0.33).clamp(260.0, 310.0);
    if (size.width > 600 && size.height > 300) {
      canvas.save();
      canvas.clipRect(Rect.fromLTWH(0, size.height - 135, sidebar, 135));
      final ribbon = Path()
        ..moveTo(sidebar - 115, size.height)
        ..lineTo(sidebar, size.height - 115)
        ..lineTo(sidebar, size.height - 78)
        ..lineTo(sidebar - 78, size.height)
        ..close();
      canvas.drawPath(ribbon,
          Paint()..color = MyTheme.accent.withOpacity(0.07));
      canvas.drawLine(Offset(sidebar - 135, size.height),
          Offset(sidebar, size.height - 135), gold);
      canvas.drawLine(Offset(sidebar - 88, size.height),
          Offset(sidebar, size.height - 88),
          Paint()..color = MyTheme.accent.withOpacity(0.30));
      canvas.restore();
    }
  }

  @override
  bool shouldRepaint(covariant _ProtorkFramePainter oldDelegate) => false;
}
