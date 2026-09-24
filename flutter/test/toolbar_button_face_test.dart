import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/desktop/widgets/toolbar_button_face.dart';

void main() {
  testWidgets('render original logo and bounded toolbar faces', (tester) async {
    final captureKey = GlobalKey();
    await tester.pumpWidget(MaterialApp(home: Scaffold(
      backgroundColor: const Color(0xFF101214),
      body: RepaintBoundary(key: captureKey, child: ColoredBox(
        color: const Color(0xFF101214),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Row(children: [
            Image.asset('assets/protork_brand.png', width: 72, height: 32,
                fit: BoxFit.contain),
            const Text('Acesso', style: TextStyle(color: Colors.yellow)),
          ]),
          Row(children: [
            for (final icon in [Icons.push_pin, Icons.bolt, Icons.chat,
                Icons.keyboard, Icons.mouse, Icons.copy,
                Icons.content_paste, Icons.swap_vert, Icons.close])
              Padding(padding: const EdgeInsets.all(5),
                child: ToolbarButtonFace(width: 56, height: 56,
                  decoration: BoxDecoration(color: const Color(0xFF30465B),
                    borderRadius: BorderRadius.circular(15)),
                  icon: Icon(icon, color: Colors.white, size: 30))),
          ]),
        ]),
      )),
    )));
    await tester.runAsync(() async {
      final context = tester.element(find.byType(Image));
      await precacheImage(const AssetImage('assets/protork_brand.png'), context);
    });
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    final boundary = captureKey.currentContext!.findRenderObject()
        as RenderRepaintBoundary;
    await tester.runAsync(() async {
      final image = await boundary.toImage(pixelRatio: 2);
      final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
      final output = File('build/toolbar-validation.png');
      await output.parent.create(recursive: true);
      await output.writeAsBytes(bytes!.buffer.asUint8List());
      image.dispose();
    });
  });
  for (final axis in Axis.values) {
    for (final submenu in [false, true]) {
      testWidgets('bounded face: $axis, submenu=$submenu', (tester) async {
        const faceKey = ValueKey('face');
        const face = ToolbarButtonFace(
          key: faceKey,
          width: 56,
          height: 56,
          decoration: BoxDecoration(color: Colors.blue),
          // Simulate artwork with a very large intrinsic size.
          icon: SizedBox(width: 1024, height: 1024,
              child: ColoredBox(color: Colors.white)),
        );
        var presses = 0;
        final button = submenu
            ? SubmenuButton(menuChildren: [
                MenuItemButton(onPressed: () {}, child: const Text('Action')),
              ], child: face)
            : MenuItemButton(onPressed: () => presses++, child: face);
        await tester.pumpWidget(MaterialApp(home: Scaffold(
          body: Align(alignment: Alignment.topLeft,
            child: SingleChildScrollView(scrollDirection: axis,
              child: MenuBar(children: [button])),
          ),
        )));
        expect(tester.takeException(), isNull);
        expect(tester.getSize(find.byKey(faceKey)), const Size(56, 56));
        final fitted = find.descendant(of: find.byKey(faceKey),
            matching: find.byType(FittedBox));
        expect(tester.getSize(fitted), const Size(42, 42));
        await tester.tap(find.byKey(faceKey));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        if (submenu) {
          expect(find.text('Action'), findsOneWidget);
        } else {
          expect(presses, 1);
        }
      });
    }
  }
}
