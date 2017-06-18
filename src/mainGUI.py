from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.core.window import Window
from kivy.uix.button import Button
import user

class LoginScreen(GridLayout):

    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        Window.size = (300, 200)
        self.cols = 1
        self.row_force_default = True
        self.row_default_height = 100
        #self.add_widget(Button(text='Deposit', size_hint_x=None, width=100))
        btn1 = Button(text='Deposit')
        btn1.bind(state=btnCallback)
        self.add_widget(btn1)
        self.add_widget(Button(text='Deposit'))
        self.add_widget(Button(text='Split'))
        self.add_widget(Button(text='Combine'))
        self.add_widget(Button(text='Spend'))

def btnCallback(instance, value):
    btnName = instance.text
    if btnName == "Deposit":
        user.deposit()
    print('My button <%s> state is <%s>' % (instance.text, value))


class MyApp(App):

    def build(self):
        return LoginScreen()


if __name__ == '__main__':
    MyApp().run()