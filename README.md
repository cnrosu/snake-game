# Snake Game

A simple snake game implemented with [pygame-ce](https://pyga.me/).

## Getting started

1. (Optional) Create and activate a virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   > **Note for Windows / Python 3.12 users:** The classic `pygame` package
   > still depends on `distutils`, which was removed in Python 3.12. This
   > project instead relies on the drop-in replacement `pygame-ce`, which
   > provides prebuilt wheels for modern Python versions and avoids the
   > missing `distutils` error during installation.

3. Run the game:

   ```bash
   python snake_game.py
   ```

### Controls

* Arrow keys / WASD — Move the snake
* Space — Restart after losing
* Esc or Q — Quit the game
