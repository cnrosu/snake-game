"""Snake Game implemented using pygame.

Run with `python snake_game.py`.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterable, List, Tuple

import pygame


class Direction(Enum):
    """Enumerates the four orthogonal movement directions."""

    UP = auto()
    DOWN = auto()
    LEFT = auto()
    RIGHT = auto()

    @property
    def vector(self) -> Tuple[int, int]:
        if self == Direction.UP:
            return (0, -1)
        if self == Direction.DOWN:
            return (0, 1)
        if self == Direction.LEFT:
            return (-1, 0)
        if self == Direction.RIGHT:
            return (1, 0)
        raise ValueError("Invalid direction")

    def opposite(self) -> "Direction":
        mapping = {
            Direction.UP: Direction.DOWN,
            Direction.DOWN: Direction.UP,
            Direction.LEFT: Direction.RIGHT,
            Direction.RIGHT: Direction.LEFT,
        }
        return mapping[self]


@dataclass
class Point:
    x: int
    y: int

    def __add__(self, other: Tuple[int, int]) -> "Point":
        dx, dy = other
        return Point(self.x + dx, self.y + dy)

    def to_pixels(self, block_size: int) -> pygame.Rect:
        return pygame.Rect(self.x * block_size, self.y * block_size, block_size, block_size)


class Snake:
    def __init__(self, initial_positions: Iterable[Point], direction: Direction) -> None:
        self.body: List[Point] = list(initial_positions)
        self.direction = direction
        self.grow_pending = 0

    @property
    def head(self) -> Point:
        return self.body[0]

    def turn(self, direction: Direction) -> None:
        if direction == self.direction or direction == self.direction.opposite():
            return
        self.direction = direction

    def move(self) -> None:
        new_head = self.head + self.direction.vector
        self.body.insert(0, new_head)
        if self.grow_pending > 0:
            self.grow_pending -= 1
        else:
            self.body.pop()

    def grow(self, segments: int = 1) -> None:
        self.grow_pending += segments

    def collides_with_self(self) -> bool:
        return self.head in self.body[1:]


class SnakeGame:
    WIDTH = 25
    HEIGHT = 18
    BLOCK_SIZE = 30
    INITIAL_LENGTH = 4
    FPS = 12

    SNAKE_COLOR = (17, 138, 178)
    SNAKE_HEAD_COLOR = (6, 75, 99)
    FOOD_COLOR = (244, 162, 97)
    BACKGROUND_COLOR = (34, 40, 49)
    GRID_COLOR = (57, 62, 70)
    TEXT_COLOR = (238, 238, 238)

    def __init__(self) -> None:
        pygame.init()
        self.surface = pygame.display.set_mode(
            (self.WIDTH * self.BLOCK_SIZE, self.HEIGHT * self.BLOCK_SIZE)
        )
        pygame.display.set_caption("Snake")
        self.clock = pygame.time.Clock()
        self.font = pygame.font.SysFont("Consolas", 24)
        self.large_font = pygame.font.SysFont("Consolas", 36, bold=True)
        self.reset()

    def reset(self) -> None:
        center_x = self.WIDTH // 2
        center_y = self.HEIGHT // 2
        initial_points = [Point(center_x - i, center_y) for i in range(self.INITIAL_LENGTH)]
        self.snake = Snake(initial_points, Direction.RIGHT)
        self.spawn_food()
        self.score = 0
        self.game_over = False

    def spawn_food(self) -> None:
        empty_spaces = {
            Point(x, y)
            for x in range(self.WIDTH)
            for y in range(self.HEIGHT)
        } - set(self.snake.body)
        self.food = random.choice(tuple(empty_spaces)) if empty_spaces else None

    def run(self) -> None:
        while True:
            self.handle_events()
            if not self.game_over:
                self.update()
            self.draw()
            self.clock.tick(self.FPS)

    def handle_events(self) -> None:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                raise SystemExit
            if event.type == pygame.KEYDOWN:
                if event.key in (pygame.K_ESCAPE, pygame.K_q):
                    pygame.quit()
                    raise SystemExit
                if event.key == pygame.K_SPACE and self.game_over:
                    self.reset()
                direction = {
                    pygame.K_UP: Direction.UP,
                    pygame.K_DOWN: Direction.DOWN,
                    pygame.K_LEFT: Direction.LEFT,
                    pygame.K_RIGHT: Direction.RIGHT,
                    pygame.K_w: Direction.UP,
                    pygame.K_s: Direction.DOWN,
                    pygame.K_a: Direction.LEFT,
                    pygame.K_d: Direction.RIGHT,
                }.get(event.key)
                if direction:
                    self.snake.turn(direction)

    def update(self) -> None:
        self.snake.move()
        if not (0 <= self.snake.head.x < self.WIDTH and 0 <= self.snake.head.y < self.HEIGHT):
            self.game_over = True
            return
        if self.snake.collides_with_self():
            self.game_over = True
            return
        if self.food and self.snake.head == self.food:
            self.snake.grow()
            self.score += 1
            self.spawn_food()

    def draw_grid(self) -> None:
        for x in range(self.WIDTH):
            pygame.draw.line(
                self.surface,
                self.GRID_COLOR,
                (x * self.BLOCK_SIZE, 0),
                (x * self.BLOCK_SIZE, self.HEIGHT * self.BLOCK_SIZE),
            )
        for y in range(self.HEIGHT):
            pygame.draw.line(
                self.surface,
                self.GRID_COLOR,
                (0, y * self.BLOCK_SIZE),
                (self.WIDTH * self.BLOCK_SIZE, y * self.BLOCK_SIZE),
            )

    def draw(self) -> None:
        self.surface.fill(self.BACKGROUND_COLOR)
        self.draw_grid()
        for segment in self.snake.body[1:]:
            pygame.draw.rect(
                self.surface,
                self.SNAKE_COLOR,
                segment.to_pixels(self.BLOCK_SIZE),
            )
        pygame.draw.rect(
            self.surface,
            self.SNAKE_HEAD_COLOR,
            self.snake.head.to_pixels(self.BLOCK_SIZE),
        )
        if self.food:
            pygame.draw.rect(
                self.surface,
                self.FOOD_COLOR,
                self.food.to_pixels(self.BLOCK_SIZE),
            )

        score_surface = self.font.render(f"Score: {self.score}", True, self.TEXT_COLOR)
        self.surface.blit(score_surface, (10, 10))

        if self.game_over:
            overlay = pygame.Surface(self.surface.get_size(), pygame.SRCALPHA)
            overlay.fill((0, 0, 0, 160))
            self.surface.blit(overlay, (0, 0))
            text = self.large_font.render("Game Over", True, self.TEXT_COLOR)
            restart = self.font.render("Press SPACE to play again", True, self.TEXT_COLOR)
            rect = text.get_rect(center=(self.surface.get_width() / 2, self.surface.get_height() / 2 - 20))
            restart_rect = restart.get_rect(
                center=(self.surface.get_width() / 2, self.surface.get_height() / 2 + 20)
            )
            self.surface.blit(text, rect)
            self.surface.blit(restart, restart_rect)

        pygame.display.flip()


def main() -> None:
    game = SnakeGame()
    game.run()


if __name__ == "__main__":
    main()
