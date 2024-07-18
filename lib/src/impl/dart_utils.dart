class DartUtils {
  static int toJavaInt32(int x) {
    bool isNegative = x & 0x80000000 != 0;
    int value = x & 0x7FFFFFFF;

    if (isNegative) {
      value = -((value ^ 0x7FFFFFFF) + 1);
    }

    return value;
  }
}